package main

import (
	"fyne.io/fyne"
	"fyne.io/fyne/widget"
)

type PasswordField struct {
	*widget.Entry
	onEnter func()
}

func NewPasswordField() *PasswordField {
	e := widget.NewEntry()
	e.Password = true
	return &PasswordField{Entry: e, onEnter: func() {}}
}

func (p *PasswordField) KeyUp(k *fyne.KeyEvent) {
	switch k.Name {
	case fyne.KeyReturn:
		p.onEnter()
	}
}
