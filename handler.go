package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/pkg/sftp"
)

// In memory pseudo file-system thing
type root struct {
	*memFile
	destination *tcpDestination
	logger      log15.Logger
	files       map[string]*memFile
	filesLock   sync.Mutex
	uploadRate  uint64
	mockErr     error
	done        <-chan struct{}
}

func newRoot(dest *tcpDestination, rate uint64, done <-chan struct{}, l log15.Logger) *root {
	r := &root{
		files:       make(map[string]*memFile),
		memFile:     newMemFile("/", true, dest, nil, rate, done, l),
		destination: dest,
		uploadRate:  rate,
		done:        done,
		logger:      l,
	}
	return r
}

// Set a mocked error that the next handler call will return.
// Set to nil to reset for no error.
func (fs *root) returnErr(err error) {
	fs.mockErr = err
}

func (fs *root) fetch(path string) (*memFile, error) {
	if path == "/" {
		return fs.memFile, nil
	}
	if file, ok := fs.files[path]; ok {
		return file, nil
	}
	return nil, os.ErrNotExist
}

// SFTP2TCPHandler returns... TODO
func SFTP2TCPHandler(dest *tcpDestination, rate uint64, done <-chan struct{}, l log15.Logger) sftp.Handlers {
	r := newRoot(dest, rate, done, l)
	return sftp.Handlers{
		FileCmd:  r,
		FileGet:  r,
		FileList: r,
		FilePut:  r,
	}
}

func (fs *root) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()
	file, err := fs.fetch(r.Filepath)
	if err != nil {
		return nil, err
	}
	if file.symlink != "" {
		file, err = fs.fetch(file.symlink)
		if err != nil {
			return nil, err
		}
	}
	return file.ReaderAt()
}

func (fs *root) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()
	/*
		file, err := fs.fetch(r.Filepath)
		if err == os.ErrNotExist {
			dir, err := fs.fetch(filepath.Dir(r.Filepath))
			if err != nil {
				return nil, err
			}
			if !dir.isdir {
				return nil, os.ErrInvalid
			}
			file = newMemFile(r.Filepath, false, fs.destination, fs.logger)
			fs.files[r.Filepath] = file
		}
	*/
	dir, err := fs.fetch(filepath.Dir(r.Filepath))
	if err != nil {
		return nil, err
	}
	if !dir.isdir {
		return nil, os.ErrInvalid
	}

	conn, err := fs.destination.getConn()
	if err != nil {
		c := cause(err)
		fs.logger.Error("Failed to make connection to TCP destination", "error", err, "type", fmt.Sprintf("%T", err), "cause", c, "causetype", fmt.Sprintf("%T", c))
		return nil, err
	}

	file := newMemFile(r.Filepath, false, fs.destination, conn, fs.uploadRate, fs.done, fs.logger)
	return file.WriterAt()
}

func (fs *root) Filecmd(r *sftp.Request) error {
	if fs.mockErr != nil {
		return fs.mockErr
	}
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()
	switch r.Method {
	case "Setstat":
		return nil
	case "Rename":
		file, err := fs.fetch(r.Filepath)
		if err != nil {
			return err
		}
		if _, ok := fs.files[r.Target]; ok {
			return &os.LinkError{Op: "rename", Old: r.Filepath, New: r.Target,
				Err: fmt.Errorf("dest file exists")}
		}
		fs.files[r.Target] = file
		delete(fs.files, r.Filepath)
	case "Rmdir", "Remove":
		_, err := fs.fetch(filepath.Dir(r.Filepath))
		if err != nil {
			return err
		}
		delete(fs.files, r.Filepath)
	case "Mkdir":
		_, err := fs.fetch(filepath.Dir(r.Filepath))
		if err != nil {
			return err
		}
		fs.files[r.Filepath] = newMemFile(r.Filepath, true, fs.destination, nil, fs.uploadRate, fs.done, fs.logger)
	case "Symlink":
		_, err := fs.fetch(r.Filepath)
		if err != nil {
			return err
		}
		link := newMemFile(r.Target, false, fs.destination, nil, fs.uploadRate, fs.done, fs.logger)
		link.symlink = r.Filepath
		fs.files[r.Target] = link
	}
	return nil
}

type listerat []os.FileInfo

// Modeled after strings.Reader's ReadAt() implementation
func (f listerat) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	var n int
	if offset >= int64(len(f)) {
		return 0, io.EOF
	}
	n = copy(ls, f[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func (fs *root) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if fs.mockErr != nil {
		return nil, fs.mockErr
	}
	fs.filesLock.Lock()
	defer fs.filesLock.Unlock()

	switch r.Method {
	case "List":
		ordered_names := []string{}
		for fn, _ := range fs.files {
			if filepath.Dir(fn) == r.Filepath {
				ordered_names = append(ordered_names, fn)
			}
		}
		sort.Strings(ordered_names)
		list := make([]os.FileInfo, len(ordered_names))
		for i, fn := range ordered_names {
			list[i] = fs.files[fn]
		}
		return listerat(list), nil
	case "Stat":
		file, err := fs.fetch(r.Filepath)
		if err != nil {
			return nil, err
		}
		return listerat([]os.FileInfo{file}), nil
	case "Readlink":
		file, err := fs.fetch(r.Filepath)
		if err != nil {
			return nil, err
		}
		if file.symlink != "" {
			file, err = fs.fetch(file.symlink)
			if err != nil {
				return nil, err
			}
		}
		return listerat([]os.FileInfo{file}), nil
	}
	return nil, nil
}

// Implements os.FileInfo, Reader and Writer interfaces.
// These are the 3 interfaces necessary for the Handlers.
type memFile struct {
	name      string
	modtime   time.Time
	symlink   string
	isdir     bool
	content   []byte
	dest      *tcpDestination
	conn      net.Conn
	logger    log15.Logger
	position  int64
	maxrate   uint64
	startTime time.Time
	done      <-chan struct{}
	err       error
	*sync.Mutex
	*sync.Cond
}

// factory to make sure modtime is set
func newMemFile(name string, isdir bool, dest *tcpDestination, conn net.Conn, maxrate uint64, done <-chan struct{}, logger log15.Logger) *memFile {
	f := &memFile{
		name:      name,
		modtime:   time.Now(),
		isdir:     isdir,
		logger:    logger,
		startTime: time.Now(),
		maxrate:   maxrate,
		dest:      dest,
		conn:      conn,
		done:      done,
	}
	f.Mutex = &sync.Mutex{}
	f.Cond = sync.NewCond(f.Mutex)
	return f
}

// Have memFile fulfill os.FileInfo interface
func (f *memFile) Name() string { return filepath.Base(f.name) }
func (f *memFile) Size() int64  { return int64(len(f.content)) }
func (f *memFile) Mode() os.FileMode {
	ret := os.FileMode(0644)
	if f.isdir {
		ret = os.FileMode(0755) | os.ModeDir
	}
	if f.symlink != "" {
		ret = os.FileMode(0777) | os.ModeSymlink
	}
	return ret
}
func (f *memFile) ModTime() time.Time { return f.modtime }
func (f *memFile) IsDir() bool        { return f.isdir }
func (f *memFile) Sys() interface{} {
	return fakeFileInfoSys()
}

// Read/Write
func (f *memFile) ReaderAt() (io.ReaderAt, error) {
	if f.isdir {
		return nil, os.ErrInvalid
	}
	return bytes.NewReader(f.content), nil
}

func (f *memFile) WriterAt() (io.WriterAt, error) {
	if f.isdir {
		return nil, os.ErrInvalid
	}
	return f, nil
}
func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.logger.Debug("WriteAt", "name", f.name, "length", len(p), "offset", off)
	f.Lock()
	defer func() {
		f.Broadcast()
		f.Unlock()
	}()
	for f.position != off {
		if f.err != nil {
			f.logger.Error("Fails because of previous error", "error", f.err, "name", f.name, "offset", off)
			return 0, f.err
		}
		f.Wait()
		// when Wait() returns the Lock is owned again
	}
	if f.err != nil {
		f.logger.Error("Fails because of previous error", "error", f.err, "name", f.name, "offset", off)
		return 0, f.err
	}
	if f.maxrate > 0 {
		currentPosition := float64(f.position * 8) // in bits
		expectedDuration := time.Duration(int64(float64(time.Second) * (currentPosition / float64(f.maxrate*1024*1024))))
		expectedTime := f.startTime.Add(expectedDuration)
		now := time.Now()
		if now.Before(expectedTime) {
			wait := expectedTime.Sub(now)
			f.logger.Debug("Wait for rate constraint", "duration", wait.Seconds())
			select {
			case <-f.done:
				f.err = context.Canceled
				return 0, context.Canceled
			case <-time.After(wait):
			}
		}
	}
	n, err := f.conn.Write(p)
	if err != nil {
		c := cause(err)
		f.logger.Error("Error happened writing to TCP destination", "error", err, "type", fmt.Sprintf("%T", err), "cause", c, "causetype", fmt.Sprintf("%T", c), "name", f.name, "offset", off)
		err = c
		f.err = err
	}
	f.position += int64(n)
	return n, err
}

func cause(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*net.OpError); ok {
		return cause(e.Err)
	}
	if e, ok := err.(*os.SyscallError); ok {
		return cause(e.Err)
	}
	return err
}

func (f *memFile) Close() error {
	f.Lock()
	defer f.Unlock()
	if f.conn == nil {
		return nil
	}
	return f.dest.releaseConn(f.conn)
}

func fakeFileInfoSys() interface{} {
	return &syscall.Stat_t{Uid: 65534, Gid: 65534}
}
