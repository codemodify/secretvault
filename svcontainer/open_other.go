//go:build !unix

package svcontainer

// nonBlocking is not needed where opening a file never waits for a writer.
const nonBlocking = 0
