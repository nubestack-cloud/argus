package changes

// delta collects one differ's field changes and the summary fragments that
// go with them.
type delta struct {
	fields  []FieldChange
	summary []string
}

// add records a change at path and any summary fragments for it.
func (d *delta) add(path string, old, new any, summary ...string) {
	d.fields = append(d.fields, FieldChange{Path: path, OldValue: old, NewValue: new})
	d.summary = append(d.summary, summary...)
}

// note adds summary fragments without a field change.
func (d *delta) note(summary ...string) { d.summary = append(d.summary, summary...) }

// merge appends another differ's output.
func (d *delta) merge(fields []FieldChange, summary []string) {
	d.fields = append(d.fields, fields...)
	d.summary = append(d.summary, summary...)
}

func (d *delta) result() ([]FieldChange, []string) { return d.fields, d.summary }

// both returns the two snapshots as *T, ok only when both are.
func both[T any](oldObj, newObj any) (*T, *T, bool) {
	a, ok1 := oldObj.(*T)
	b, ok2 := newObj.(*T)
	return a, b, ok1 && ok2
}
