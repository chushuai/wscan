package rsync

type SumStruct struct {
	FileLen   uint64     // totol file length
	Count     uint64     // how many chunks
	Remainder uint64     // fileLen % blockLen
	BlockLen  uint64     // block length
	Sum2Len   uint64     // sum2 length
	SumList   []SumChunk // chunks
}

type SumChunk struct {
	FileOffset int64
	ChunkLen   uint
	Sum1       uint32
	Sum2       []byte
}
