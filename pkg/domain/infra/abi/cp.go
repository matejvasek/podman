package abi

import (
	"archive/tar"
	"context"
	"github.com/containers/buildah/copier"
	"github.com/containers/buildah/pkg/chrootuser"
	"github.com/containers/podman/v2/libpod"
	"github.com/containers/podman/v2/libpod/define"
	"github.com/containers/podman/v2/pkg/domain/entities"
	"github.com/containers/storage/pkg/archive"
	"github.com/containers/storage/pkg/idtools"
	securejoin "github.com/cyphar/filepath-securejoin"
	rsystem "github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (ic *ContainerEngine) ContainerCp(ctx context.Context, source, dest string, options entities.ContainerCpOptions) (*entities.ContainerCpReport, error) {
	extract := options.Extract

	srcCtr, srcPath, err := parsePath(ic.Libpod, source)
	if err != nil {
		return nil, err
	}
	destCtr, destPath, err := parsePath(ic.Libpod, dest)
	if err != nil {
		return nil, err
	}

	if (srcCtr == nil && destCtr == nil) || (srcCtr != nil && destCtr != nil) {
		return nil, errors.Errorf("invalid arguments %s, %s you must use exactly one container", source, dest)
	}

	if len(srcPath) == 0 || len(destPath) == 0 {
		return nil, errors.Errorf("invalid arguments %s, %s you must specify paths", source, dest)
	}
	ctr := srcCtr
	isFromHostToCtr := ctr == nil
	if isFromHostToCtr {
		ctr = destCtr
	}

	mountPoint, err := ctr.Mount()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := ctr.Unmount(false); err != nil {
			logrus.Errorf("unable to umount container '%s': %q", ctr.ID(), err)
		}
	}()

	if options.Pause {
		if err := ctr.Pause(); err != nil {
			// An invalid state error is fine.
			// The container isn't running or is already paused.
			// TODO: We can potentially start the container while
			// the copy is running, which still allows a race where
			// malicious code could mess with the symlink.
			if errors.Cause(err) != define.ErrCtrStateInvalid {
				return nil, err
			}
		} else {
			// Only add the defer if we actually paused
			defer func() {
				if err := ctr.Unpause(); err != nil {
					logrus.Errorf("Error unpausing container after copying: %v", err)
				}
			}()
		}
	}

	user, err := getUser(mountPoint, ctr.User())
	if err != nil {
		return nil, err
	}
	idMappingOpts, err := ctr.IDMappings()
	if err != nil {
		return nil, errors.Wrapf(err, "error getting IDMappingOptions")
	}

	if isFromHostToCtr {
		// from host to container

		mountPoint, destPath, err = fixupPath(ic.Libpod, ctr, mountPoint, destPath)
		if err != nil {
			return nil, err
		}

		dir, newName, err := getDirAndRename(destPath, getRemoteStatsGetter(mountPoint))
		if err != nil {
			return nil, err
		}

		destOwner := idtools.IDPair{UID: int(user.UID), GID: int(user.GID)}

		opts := copier.PutOptions{
			UIDMap:     idMappingOpts.UIDMap,
			GIDMap:     idMappingOpts.GIDMap,
			ChownDirs:  &destOwner,
			ChownFiles: &destOwner,
		}

		var reader io.ReadCloser
		if srcPath == "-" {
			reader = os.Stdin
		} else if extract {
			reader, err = os.Open(srcPath)
			if err != nil {
				return nil, err
			}
		} else {
			reader, err = archive.TarResourceRebase(srcPath, newName)
			if err != nil {
				return nil, err
			}
		}
		defer reader.Close()

		err = copier.Put(mountPoint, dir, opts, reader)
		if err != nil {
			return nil, errors.Wrap(err, "failed to put")
		}
		return &entities.ContainerCpReport{}, err

	} else {
		// from container to host
		mountPoint, srcPath, err := fixupPath(ic.Libpod, ctr, mountPoint, srcPath)
		if err != nil {
			return nil, err
		}

		destOwner := idtools.IDPair{UID: os.Getuid(), GID: os.Getgid()}

		var writer io.WriteCloser
		if destPath == "-" {
			writer = os.Stdout
		} else {
			writer, err = untarToPath(destPath)
			if err != nil {
				return nil, err
			}
		}
		defer writer.Close()

		opts := copier.GetOptions{
			UIDMap:             idMappingOpts.UIDMap,
			GIDMap:             idMappingOpts.GIDMap,
			ChownDirs:          &destOwner,
			ChownFiles:         &destOwner,
			KeepDirectoryNames: true,
		}

		srcPath, err = securejoin.SecureJoin(mountPoint, srcPath)
		if err != nil {
			return nil, err
		}
		err = copier.Get(mountPoint, "", opts, []string{srcPath}, writer)
		if err != nil {
			return nil, err
		}

		return &entities.ContainerCpReport{}, err
	}
}

func getUser(mountPoint string, userspec string) (specs.User, error) {
	uid, gid, _, err := chrootuser.GetUser(mountPoint, userspec)
	u := specs.User{
		UID:      uid,
		GID:      gid,
		Username: userspec,
	}
	if !strings.Contains(userspec, ":") {
		groups, err2 := chrootuser.GetAdditionalGroupsForUser(mountPoint, uint64(u.UID))
		if err2 != nil {
			if errors.Cause(err2) != chrootuser.ErrNoSuchUser && err == nil {
				err = err2
			}
		} else {
			u.AdditionalGids = groups
		}

	}
	return u, err
}

func parsePath(runtime *libpod.Runtime, path string) (*libpod.Container, string, error) {
	pathArr := strings.SplitN(path, ":", 2)
	if len(pathArr) == 2 {
		ctr, err := runtime.LookupContainer(pathArr[0])
		if err == nil {
			return ctr, pathArr[1], nil
		} else {
			return nil, "", err
		}
	}
	return nil, path, nil
}

func getStatsFromCrt(mountPoint, ctrPath string) (*copier.StatForItem, error) {
	crtPath, err:= securejoin.SecureJoin(mountPoint, ctrPath)
	if err != nil {
		return nil, err
	}
	stats, err := copier.Stat(mountPoint, "", copier.StatOptions{}, []string{crtPath})
	if err != nil {
		return nil, err
	}
	if len(stats) <= 0 || len(stats[0].Globbed) <= 0 {
		return nil, errors.Wrapf(os.ErrNotExist, "couldn't get stats for file %s: %q", ctrPath, stats[0].Error)
	}
	return stats[0].Results[stats[0].Globbed[0]], nil
}


// transforms one tar read stream to another tar read stream
// it changes first part of path
// e.g. if newName=="new" then { "adir/a.txt" , "adir/b.txt" } -> { "new/a.txt" , "new/b.txt" }
// it is used if `cp` is doing rename see `getDirAndRename`
func rebase(origReader *io.PipeReader, newName string) (*io.PipeReader, error) {
	if newName == "" {
		return origReader, nil
	}

	newReader, pw := io.Pipe()
	go func() {
		var err error
		defer origReader.Close()
		defer pw.CloseWithError(err)

		tr := tar.NewReader(origReader)
		tw := tar.NewWriter(pw)
		defer tw.Close()

		for {
			var header *tar.Header
			header, err = tr.Next()

			switch {
			case err == io.EOF:
				return
			case err != nil:
				return
			case header == nil:
				continue
			}
			parts := strings.Split(header.Name, "/")
			if len(parts) >= 2 {
				header.Name = newName + "/" + strings.Join(parts[1:], "/")
			} else {
				header.Name = newName
			}
			tw.WriteHeader(header)
			io.Copy(tw, tr)
		}
	}()

	return newReader, nil
}

type stats interface {
	IsDirectory() bool
}

type statsGetter = func(path string) (stats, error)

func getRemoteStatsGetter(mountPoint string) statsGetter {
	return func(path string) (stats, error) {
		impl, err := getStatsFromCrt(mountPoint, path)
		if err != nil {
			return nil, err
		}
		return &remoteStats{impl}, nil
	}
}

func getLocalStatsGetter() statsGetter {
	return func(path string) (stats, error) {
		impl, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return &localStats{impl}, nil
	}
}

// helps to detect if `cp` is doing rename
// in case of rename the `newName` is nonempty
func getDirAndRename(path string, stats statsGetter) (dir string, newName string, err error) {

	fi, err := stats(path)

	if err != nil && !os.IsNotExist(errors.Cause(err)) {
		return
	}

	if os.IsNotExist(errors.Cause(err)) {
		if strings.HasSuffix(path, string(filepath.Separator)) {
			err = errors.Wrapf(os.ErrNotExist, "destination directory %s doesn't exists", path)
			return
		}
		dir = filepath.Dir(path)
		newName = filepath.Base(path)
		fi, err = stats(dir)
		if err != nil && !os.IsNotExist(errors.Cause(err)) {
			return
		}
		if os.IsNotExist(errors.Cause(err)) {
			err = errors.Wrapf(os.ErrNotExist, "destination directory %s doesn't exists", dir)
			return
		}
		if !fi.IsDirectory() {
			err = errors.Wrapf(os.ErrExist, "destination directory %s is a regular file", dir)
			return
		}
	} else {
		if fi.IsDirectory() {
			dir = path
			newName = ""
		} else {
			dir = filepath.Dir(path)
			newName = filepath.Base(path)
		}
	}
	return
}

func untarToPath(destPath string) (io.WriteCloser, error) {

	dir, newName, err := getDirAndRename(destPath, getLocalStatsGetter())
	if err != nil {
		return nil, err
	}

	reader, writer := io.Pipe()
	reader, err = rebase(reader, newName)
	if err != nil {
		return nil, err
	}
	go func() {
		var err error
		defer reader.CloseWithError(err)
		err = archive.Untar(reader, dir, &archive.TarOptions{
			InUserNS: rsystem.RunningInUserNS(),
		})
	}()

	return writer, nil

}

type remoteStats struct {
	impl *copier.StatForItem
}

func (r *remoteStats) IsDirectory() bool {
	return r.impl.IsDir
}

type localStats struct {
	impl os.FileInfo
}

func (l localStats) IsDirectory() bool {
	return l.impl.IsDir()
}

func fixupPath(runtime *libpod.Runtime, ctr*libpod.Container, mountPoint, ctrPath string) (string, string, error) {
	if isVol, volDestName, volName := isVolumeDestName(ctrPath, ctr); isVol { //nolint(gocritic)
		newMountPoint, path, err := pathWithVolumeMount(runtime, volDestName, volName, ctrPath)
		if err != nil {
			return "", "", errors.Wrapf(err, "error getting source path from volume %s", volDestName)
		}
		mountPoint = newMountPoint
		ctrPath = path
	} else if isBindMount, mount := isBindMountDestName(ctrPath, ctr); isBindMount { //nolint(gocritic)
		newMountPoint, path, err := pathWithBindMountSource(mount, ctrPath)
		if err != nil {
			return "", "", errors.Wrapf(err, "error getting source path from bind mount %s", mount.Destination)
		}
		mountPoint = newMountPoint
		ctrPath = path
	} else if !filepath.IsAbs(ctrPath) { //nolint(gocritic)
		endsWithSep := strings.HasSuffix(ctrPath, string(filepath.Separator))
		ctrPath = filepath.Join(ctr.WorkingDir(), ctrPath)
		if endsWithSep {
			ctrPath = ctrPath + string(filepath.Separator)
		}
	}
	return mountPoint, ctrPath, nil
}

func isVolumeDestName(path string, ctr *libpod.Container) (bool, string, string) {
	separator := string(os.PathSeparator)
	if filepath.IsAbs(path) {
		path = strings.TrimPrefix(path, separator)
	}
	if path == "" {
		return false, "", ""
	}
	for _, vol := range ctr.Config().NamedVolumes {
		volNamePath := strings.TrimPrefix(vol.Dest, separator)
		if matchVolumePath(path, volNamePath) {
			return true, vol.Dest, vol.Name
		}
	}
	return false, "", ""
}

func pathWithVolumeMount(runtime *libpod.Runtime, volDestName, volName, path string) (string, string, error) {
	destVolume, err := runtime.GetVolume(volName)
	if err != nil {
		return "", "", errors.Wrapf(err, "error getting volume destination %s", volName)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(string(os.PathSeparator), path)
	}
	return destVolume.MountPoint(), strings.TrimPrefix(path, volDestName), err
}

func isBindMountDestName(path string, ctr *libpod.Container) (bool, specs.Mount) {
	separator := string(os.PathSeparator)
	if filepath.IsAbs(path) {
		path = strings.TrimPrefix(path, string(os.PathSeparator))
	}
	if path == "" {
		return false, specs.Mount{}
	}
	for _, m := range ctr.Config().Spec.Mounts {
		if m.Type != "bind" {
			continue
		}
		mDest := strings.TrimPrefix(m.Destination, separator)
		if matchVolumePath(path, mDest) {
			return true, m
		}
	}
	return false, specs.Mount{}
}

func matchVolumePath(path, target string) bool {
	pathStr := filepath.Clean(path)
	target = filepath.Clean(target)
	for len(pathStr) > len(target) && strings.Contains(pathStr, string(os.PathSeparator)) {
		pathStr = pathStr[:strings.LastIndex(pathStr, string(os.PathSeparator))]
	}
	return pathStr == target
}

func pathWithBindMountSource(m specs.Mount, path string) (string, string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(string(os.PathSeparator), path)
	}
	return m.Source, strings.TrimPrefix(path, m.Destination), nil
}