package xsk

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	XDP_BPFFS_ENVVAR       = "LIBXDP_BPFFS"
	XDP_BPFFS_MOUNT_ENVVAR = "LIBXDP_BPFFS_AUTOMOUNT"
	BPF_DIR_MNT            = "/sys/fs/bpf"
	RUNDIR                 = "/run"
	XDP_SUBDIR             = "xdp"
)

var (
	bpfMntCached bool
	bpfWrkDir    string
)

// mkStateSubdir 在给定的父目录下创建名为 "xdp" 的子目录。
func mkStateSubdir(parent string) (string, error) {
	// 使用 fmt.Sprintf 构建目录路径
	dir := fmt.Sprintf("%s/xdp", parent)
	// 尝试创建目录，如果目录已存在，不返回错误

	err := os.Mkdir(dir, unix.S_IRWXU) // S_IRWXU 权限 = 0700
	if err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	return dir, nil
}

// findBpffs attempts to locate the BPF filesystem mount point.
func findBpffs() (string, error) {
	if bpfMntCached {
		return bpfWrkDir, nil
	}

	envVal, has := os.LookupEnv(XDP_BPFFS_MOUNT_ENVVAR)
	mount := false
	if has && envVal == "1" {
		mount = true
	}
	envDir, has := os.LookupEnv(XDP_BPFFS_ENVVAR)
	if !has {
		envDir = BPF_DIR_MNT
	}

	mnt, err := bpfFindMntptSingle(envDir, mount)
	if err != nil {
		fmt.Printf("No bpffs found at %s\n", envDir)
		return "", err
	} else {
		bpfMntCached = true
		bpfWrkDir = mnt
		return bpfWrkDir, nil
	}
}

// bpfIsValidMntpt 检查给定的挂载点是否为有效的BPF文件系统。
func bpfIsValidMntpt(mnt string) bool {
	var statfs unix.Statfs_t

	// 获取文件系统信息
	err := unix.Statfs(mnt, &statfs)
	if err != nil {
		// 如果发生错误，返回false
		return false
	}

	// 检查文件系统类型是否等于 BPF 文件系统的魔数
	if statfs.Type != unix.BPF_FS_MAGIC {
		return false
	}

	return true
}

// bpfFindMntptSingle is a placeholder for the logic to find the BPF mount point.
func bpfFindMntptSingle(dir string, mount bool) (string, error) {
	if !bpfIsValidMntpt(dir) {
		if !mount {
			return "", fmt.Errorf("no bpffs found at %s", dir)
		}
		// No bpffs found at %s, mounting a new one

		err := bpfMntFs(dir)
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}

func bpfMntFs(target string) error {
	bindDone := false

retry:
	// 第一次挂载：尝试将 target 变为私有的挂载点
	err := unix.Mount("", target, "none", unix.MS_PRIVATE|unix.MS_REC, "")
	if err != nil {
		if err != unix.EINVAL || bindDone {
			return fmt.Errorf("mount --make-private %s failed: %w", target, err)
			// 如果不是EINVAL错误，或已经完成bind操作，返回错误
		}

		// 尝试进行 bind 挂载
		err = unix.Mount(target, target, "none", unix.MS_BIND, "")
		if err != nil {
			return fmt.Errorf("mount --bind %s %s failed: %w", target, target, err)
		}

		bindDone = true
		goto retry
	}

	err = unix.Mount("bpf", target, "bpf", 0, "mode=0700")
	if err != nil {
		return fmt.Errorf("mount -t bpf bpf %s failed: %w", target, err)
	}

	return nil
}

// getBpffsDir retrieves the directory for storing state.
func getBpffsDir() (string, error) {
	parent, err := findBpffs()
	if err != nil {
		return "", err
	}

	bpffs_dir, err := mkStateSubdir(parent)
	if err != nil {
		return "", err
	}

	return bpffs_dir, nil
}

// getLockDir retrieves the directory for locks, falling back to /run if necessary.
func getLockDir() (string, error) {
	dir, err := getBpffsDir()
	if err == nil {
		return dir, nil
	}

	rundir, err := mkStateSubdir(RUNDIR)
	if err != nil {
		return "", err
	}
	return rundir, nil
}

// xdpLockAcquire acquires an exclusive lock on the directory.
func xdpLockAcquire() (*os.File, error) {
	dir, err := getLockDir()
	if err != nil {
		return nil, err
	}

	lockFile, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("couldn't open lock directory at %s: %w", dir, err)
	}

	err = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX)
	if err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("couldn't flock fd %d: %w", lockFile.Fd(), err)
	}

	// fmt.Printf("Acquired lock from %s with fd %d\n", dir, lockFile.Fd())
	return lockFile, nil
}

// xdpLockRelease releases the lock on the directory.
func xdpLockRelease(lockFile *os.File) error {
	err := unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	if err != nil {
		return fmt.Errorf("couldn't unlock fd %d: %w", lockFile.Fd(), err)
	}

	fmt.Printf("Released lock fd %d\n", lockFile.Fd())
	lockFile.Close()
	return nil
}
