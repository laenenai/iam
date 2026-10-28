package domain

// Relation names an edge between a subject and an object.
type Relation string

const (
	Parent     Relation = "parent"
	Owner      Relation = "owner"
	Editor     Relation = "editor"
	Commenter  Relation = "commenter"
	Viewer     Relation = "viewer"
	CanShare   Relation = "can_share"
	CanDelete  Relation = "can_delete"
	CanView    Relation = "can_view"
	CanEdit    Relation = "can_edit"
	CanComment Relation = "can_comment"
	Member     Relation = "member"
	Admin      Relation = "admin"
)

// Rank returns the pinned ladder rank; relations outside the ladder are 0.
func (r Relation) Rank() int {
	switch r {
	case Viewer:
		return 1
	case Commenter:
		return 2
	case Editor:
		return 3
	case Owner:
		return 4
	default:
		return 0
	}
}

func (r Relation) IsBase() bool {
	switch r {
	case Owner, Editor, Commenter, Viewer:
		return true
	default:
		return false
	}
}

func (r Relation) IsGrantable() bool {
	switch r {
	case Owner, Editor, Commenter, Viewer, CanDelete:
		return true
	default:
		return false
	}
}
