package main

import (
	"fyne.io/fyne"
	"fyne.io/fyne/widget"
)

type PasswordField struct {
	widget.Entry
	onEnter func()
}

func NewPasswordField() *PasswordField {
	e := &PasswordField{}
	e.ExtendBaseWidget(e)
	e.Password = true
	return e
}

func (p *PasswordField) KeyUp(k *fyne.KeyEvent) {
	p.Entry.KeyUp(k)
	switch k.Name {
	case fyne.KeyReturn:
		p.onEnter()
	}
}
