__author__ = 'zeizyy'
from sudoku import sudoku

class sudoku_s:
    def __init__(self):
        self.s_list = []
        self.s_list.append(sudoku())
        self.s_list.append(sudoku())
        self.s_list.append(sudoku())
        self.s_list.append(sudoku())
        self.s_list.append(sudoku())

    def load(self,file0,file1,file2,file3, file4):
        self.s_list[0].initialize(file0);
        self.s_list[1].initialize(file1);
        self.s_list[2].initialize(file2);
        self.s_list[3].initialize(file3);
        self.s_list[4].initialize(file4);

    