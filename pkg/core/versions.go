package core

// CurrentClientLibraryVersion returns the current client library version used
// for feature compatibility support between client and server. Currently I
// don't intend to connect this to the library tag version in any way.
//
// When adding new client versions comment out older versions and add new
// version below with a description of the reason for the new version.
func CurrentClientLibraryVersion() uint32 {
	// Support for randomizing destination port for phantom connection
	// https://github.com/refraction-networking/gotapdance/pull/108
	return 3

	// // Selection algorithm update - Oct 27, 2022 -- Phantom selection version rework again to use
	// // hkdf for actual uniform distribution across phantom subnets.
	// // https://github.com/refraction-networking/conjure/pull/145
	// return 2

	// // Initial inclusion of client version - added due to update in phantom
	// // selection algorithm that is not backwards compatible to older clients.
	// return 1

	// // No client version indicates any client before this change.
	// return 0
}
