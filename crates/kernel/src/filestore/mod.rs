//! fwe's own file store in memory: the files of a tmpfs, of `/dev/shm` and
//! of memfds, which Linux keeps in memory, kept in memory every fwe process
//! maps, never in files on disk.

pub mod arena;
pub mod data;
pub mod desc;
pub mod fs;
pub mod io;
pub mod tree;
