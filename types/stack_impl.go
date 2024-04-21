package types

import (
	"errors"
	"fmt"
)

type Stack [][]byte

func (s *Stack) Push(input []byte) {
	if s == nil || len(*s) == 0 {
		*s = make([][]byte, 0)
	}
	*s = append(*s, input)
}

func (s *Stack) Pop() ([]byte, error) {
	if s.IsEmpty() {
		fmt.Println("Stack is empty")
		return []byte{}, errors.New("Stack is empty")
	}
	// now let's get the top most element index
	topIndex := len(*s) - 1
	// now get actual element in this position
	topElement := (*s)[topIndex]
	// now pop off this item
	*s = (*s)[:topIndex]
	return topElement, nil

}
func (s *Stack) IsEmpty() bool {
	return len(*s) == 0
}

func (s *Stack) StackLen() int {
	return len(*s)
}
