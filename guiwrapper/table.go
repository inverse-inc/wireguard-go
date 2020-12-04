package main

import (
	"fyne.io/fyne"
	"fyne.io/fyne/container"
	"fyne.io/fyne/widget"
)

type Table struct {
	columnsRows [][]*widget.Label
	columns     []*fyne.Container
	container   *fyne.Container
}

func NewTable() *Table {
	return &Table{columnsRows: [][]*widget.Label{}, columns: []*fyne.Container{}}
}

func (t *Table) Update(headings []string, rows [][]string) {
	columnsData := rowsToColumns(headings, rows)
	for i, col := range columnsData {
		if len(t.columnsRows) <= i {
			t.columnsRows = append(t.columnsRows, []*widget.Label{})
		}
		row := t.columnsRows[i]
		columnData := append([]string{headings[i]}, col...)
		for j, elem := range columnData {
			if len(row) <= j {
				row = append(row, widget.NewLabel(elem))
			}
			row[j].Text = elem
		}
		t.columnsRows[i] = row

		if len(t.columns) <= i {
			t.columns = append(t.columns, container.NewGridWithColumns(1, []fyne.CanvasObject{}...))
		}

		objects := []fyne.CanvasObject{}
		for _, o := range t.columnsRows[i] {
			objects = append(objects, o)
		}

		column := t.columns[i]
		column.Objects = objects
		column.Refresh()
	}

	objects := []fyne.CanvasObject{}
	for _, o := range t.columns {
		objects = append(objects, o)
	}

	container := t.GetContainer()
	container.Objects = objects
	container.Refresh()
}

func (t *Table) GetContainer() *fyne.Container {
	if t.container == nil {
		t.container = container.NewHBox()
	}
	return t.container
}
