package ci

type Testing interface {
	FailNow()
	SkipNow()
}
