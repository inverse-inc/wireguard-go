package main

import (
	"fyne.io/fyne"
	"fyne.io/fyne/container"
	"fyne.io/fyne/widget"
)

func makeTable(headings []string, rows [][]string) *fyne.Container {
	columns := rowsToColumns(headings, rows)
	objects := []fyne.CanvasObject{}
	for i, col := range columns {
		elems := []fyne.CanvasObject{
			widget.NewLabelWithStyle(headings[i], fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		}
		for _, elem := range col {
			elems = append(elems, widget.NewLabel(elem))
		}
		objects = append(objects, container.NewGridWithColumns(1, elems...))
	}
	return container.NewHBox(objects...)
}

func rowsToColumns(headings []string, rows [][]string) [][]string {
	columns := make([][]string, len(headings))
	for _, row := range rows {
		for colK := range row {
			columns[colK] = append(columns[colK], row[colK])
		}
	}
	return columns
}
