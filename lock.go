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

// findBpffs 尝试找到 BPF 文件系统的挂载点。
// 它首先检查挂载点是否已缓存，如果可用则返回它。
// 如果没有缓存，它会检查环境变量以确定是否应该挂载文件系统以及在哪里查找它。
// 然后它尝试找到挂载点，如果成功则缓存结果。
//
// 返回值:
// - 表示 BPF 文件系统挂载点的字符串。
// - 如果找不到挂载点，则返回错误。
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
		return "", fmt.Errorf("no bpffs found at %s", envDir)
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

// bpfFindMntptSingle 尝试在指定目录找到 BPF 文件系统挂载点。
// 如果该目录不是有效的 BPF 挂载点且 mount 标志为 true，它将尝试在指定目录挂载一个新的 BPF 文件系统。
//
// 参数:
//   - dir: 要检查的目录是否为 BPF 文件系统挂载点。
//   - mount: 一个布尔标志，指示如果未找到 BPF 文件系统是否挂载新的 BPF 文件系统。
//
// 返回值:
//   - 如果目录是有效的 BPF 挂载点或成功挂载了新的 BPF 文件系统，则返回表示该目录的字符串。
//   - 如果目录不是有效的 BPF 挂载点且挂载新的 BPF 文件系统失败，则返回错误。
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

// bpfMntFs 尝试在指定的目标目录挂载 BPF 文件系统。
// 它首先尝试将目标目录变为私有挂载点。如果失败并返回 EINVAL 错误，它会尝试在目标目录上进行绑定挂载，并重试将其设为私有。
// 一旦目标目录成为私有挂载点，它会以 0700 模式挂载 BPF 文件系统。
//
// 参数:
//   - target: 要挂载 BPF 文件系统的目录。
//
// 返回值:
//   - error: 如果任何挂载操作失败，则返回错误，否则返回 nil。
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

// getBpffsDir 函数用于获取 BPF 文件系统目录。
// 它首先调用 findBpffs 函数查找父目录，如果失败则返回错误。
// 然后调用 mkStateSubdir 函数在父目录下创建子目录，如果失败则返回错误。
// 最后返回创建的 BPF 文件系统目录路径。
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

// getLockDir 尝试使用 getBpffsDir 检索 BPF 文件系统目录。
// 如果成功，它返回目录路径。如果 getBpffsDir 失败，它会在 RUNDIR 下创建一个子目录
// 使用 mkStateSubdir 并返回新创建的子目录的路径。如果创建子目录失败，它会返回一个错误。
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

// xdpLockAcquire 尝试获取目录上的排他锁。
// 它返回锁定目录的文件描述符，如果发生任何错误，则返回错误。
//
// 返回值:
// - *os.File: 锁定目录的文件描述符。
// - error: 如果无法获取锁或打开目录时出现问题，则返回错误。
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

// xdpLockRelease 释放指定锁文件上的文件锁。
//
// 参数:
//   - lockFile (*os.File): 要释放锁的文件。
//
// 返回值:
//   - error: 如果解锁操作失败，则返回错误，否则返回 nil。
//
// 此函数使用 unix.Flock 系统调用来释放与提供的 lockFile 关联的文件描述符上的锁。
// 如果解锁操作成功，则关闭该文件。如果解锁操作失败，则返回一个格式化的错误消息，指示失败。
func xdpLockRelease(lockFile *os.File) error {
	err := unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	if err != nil {
		return fmt.Errorf("couldn't unlock fd %d: %w", lockFile.Fd(), err)
	}

	// fmt.Printf("Released lock fd %d\n", lockFile.Fd())
	lockFile.Close()
	return nil
}
