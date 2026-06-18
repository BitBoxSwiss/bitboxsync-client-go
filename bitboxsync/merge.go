// SPDX-License-Identifier: Apache-2.0

package bitboxsync

// PreferLocal returns a merge function that always resolves conflicts in favor
// of the local value.
func PreferLocal[T any]() MergeFunc[T] {
	return func(_ string, _ *T, local T, _ T) (T, bool, error) {
		return local, true, nil
	}
}

// PreferRemote returns a merge function that always resolves conflicts in favor
// of the remote value.
func PreferRemote[T any]() MergeFunc[T] {
	return func(_ string, _ *T, _ T, remote T) (T, bool, error) {
		return remote, true, nil
	}
}

// NoMerge returns a merge function that leaves conflicts unresolved so the app
// can resolve them manually.
func NoMerge[T any]() MergeFunc[T] {
	return func(_ string, _ *T, local T, _ T) (T, bool, error) {
		return local, false, nil
	}
}
