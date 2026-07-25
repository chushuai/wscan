package rsync

// Reference: rsync 2.6.0
// --exclude & --exclude-from

/* These default ignored items come from the CVS manual.
* "RCS SCCS CVS CVS.adm RCSLOG cvslog.* tags TAGS"
* " .make.state .nse_depinfo *~ #* .#* ,* _$* *$"
* " *.old *.bak *.BAK *.orig *.rej .del-*"
* " *.a *.olb *.o *.obj *.so *.exe"
* " *.Z *.elc *.ln core"
The rest we added to suit ourself.
* " .svn/ .bzr/"
*/

// Filter List
type ExclusionList []string

// This is only called by the client
func (e ExclusionList) SendExlusionList(conn *Conn) error {
	// For each item, send its length first
	for _, p := range e {
		plen := int32(len(p))
		if err := conn.WriteInt(plen); err != nil {
			return err
		}
		if _, err := conn.Write([]byte(p)); err != nil {
			return err
		}
	}

	if err := conn.WriteInt(EXCLUSION_END); err != nil {
		return err
	}
	return nil
}
