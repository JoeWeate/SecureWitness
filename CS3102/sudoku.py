__author__ = 'yl3ak'

import copy

class sudoku:
    rows = []
    columns = []
    row_cap = []
    col_cap = []
    row_cap_max = -1;
    col_cap_max = -1;

    def __init__(self):
        self.row_cap = [0]*9
        self.col_cap = [0]*9
        for i in range(9):
            self.rows.append([])
            self.columns.append([])


    def __str__(self):
        string = self.get_row(0).__str__() + "\n"
        for i in range(1,9):
            string = string + self.get_row(i).__str__() +"\n"

        return string

    def initialize(self,file_name):
        file = open(file_name,"r")
        row_num = 0
        for lines in file:
            for symbols in lines:
                if symbols is not "\n":
                    self.rows[row_num].append(int(symbols))
            row_num = row_num + 1

        for r in self.rows:
            column_num = 0
            for item in r:
                self.columns[column_num].append(item)
                column_num = column_num + 1

        for i in range(9):
            count = 0
            c = self.columns[i]
            for item in c:
                if item != 0:
                    count = count +1
            self.col_cap[i] = count
        self.col_cap_max = self.col_cap.index(max(self.col_cap))

        for i in range(9):
            count = 0
            r = self.rows[i]
            for item in r:
                if item != 0:
                    count = count + 1
            self.row_cap[i] = count
        self.row_cap_max = self.row_cap.index(max(self.row_cap))


    def get_row(self,row_num):
        return self.rows[row_num]


    def get_column(self,column_num):
        return self.columns[column_num]

    def get_region(self,row_num,column_num):
        region_dict = {0:0,1:0,2:0,3:3,4:3,5:3,6:6,7:6,8:6}
        region = []
        r = region_dict[row_num]
        c = region_dict[column_num]
        rlimit = r+3
        climit = c+3
        for i in range(r,rlimit):
            for j in range(c,climit):
                region.append(self.get_row(i)[j])
        return region

    def is_row_conflict(self,value,row_num):
        if value in self.get_row(row_num):
            return True
        else:
            return False

    def is_column_conflict(self,value,column_num):
        if value in self.get_column(column_num):
            return True
        else:
            return False

    def is_region_conflict(self,value,row_num,column_num):
        if value in self.get_region(row_num,column_num):
            return True
        else:
            return False

    def fill_in_blank(self,value,row_num,column_num):
        self.rows[row_num][column_num] = value
        self.columns[column_num][row_num] = value

    def is_empty(self,row_num,column_num):
        if self.get_row(row_num)[column_num] == 0:
            return True
        else:
            return False

    def is_conflict(self,value,row,column):
        if not self.is_column_conflict(value,column) and not self.is_row_conflict(value,row) and not self.is_region_conflict(value,row,column):
            return False
        else:
            return True

    def is_solved(self):

        for i in range(self.n):
            for j in range(self.n):
                if self.rows[i][j] == 0:
                    return False

        return True

    def max_less_than_nine_row(self):
        max = -1
        counter = 0
        index = -1
        for r in self.row_cap:
            if r > max and r < 9:
                max = r
                index = counter
            counter += 1
        return index

    def max_less_than_nine_col(self):
        max = -1
        counter = 0
        index = -1
        for c in self.col_cap:
            if c > max and c < 9:
                max = c
                index = counter
            counter += 1
        return index

    def real_size(self):
        count = 0
        for r in self.rows:
            count = count + r.count(0)
        return 81-count

    def deep_copy(self):
        list = []
        for j in range(9):
            list.append([0]*9)
        for i in range(9):
            for j in range(9):
                list[i][j]=self.rows[i][j]
        return list

def find_empty_location(sudoku):
    for row in range(9):
        for col in range(9):
            if sudoku.is_empty(row,col):
                return [row,col]
    return False

def find_empty_location2(sudoku):
    c_max = sudoku.col_cap_max
    r_max = sudoku.row_cap_max
    min_diff = 9
    c_index = 0
    for col in range(9):
        if sudoku.is_empty(r_max,col):
            if abs(col-c_max) < min_diff:
                min_diff=abs(col-c_max)
                c_index = col
    return [r_max,c_index]

def find_empty_location3(sudoku):
    c_max = sudoku.col_cap_max
    r_max = sudoku.row_cap_max
    min_diff = 9
    c_index = 0
    for col in range(9):
        if sudoku.is_empty(r_max,col):
            return [r_max,col]

def solve(sudoku,l):
    if not find_empty_location(sudoku):
    	l.append(copy.deepcopy(sudoku.rows))
    	print(sudoku)

    	return True

    else:
        coor = find_empty_location3(sudoku)
        row = coor[0]
        col = coor[1]

    for num in range(1,10):
        if not sudoku.is_conflict(num,row,col):
            sudoku.fill_in_blank(num,row,col)
            sudoku.col_cap[col] += 1
            sudoku.row_cap[row] += 1
            col_cap_max_before = sudoku.col_cap_max
            row_cap_max_before = sudoku.row_cap_max
            if sudoku.col_cap[col] == 9:
                sudoku.col_cap_max = sudoku.max_less_than_nine_col()
            if sudoku.row_cap[row] == 9:
                sudoku.row_cap_max = sudoku.max_less_than_nine_row()
            solve(sudoku,l)
            sudoku.fill_in_blank(0,row,col)
            sudoku.col_cap[col] -= 1
            sudoku.row_cap[row] -= 1
            if sudoku.col_cap[col] == 8:
                sudoku.col_cap_max = col_cap_max_before
            if sudoku.row_cap[row] == 8:
                sudoku.row_cap_max = row_cap_max_before
    return False

def solve1(sudoku,l):
    coor = find_empty_location2(sudoku)
    row = coor[0]
    col = coor[1]
    if row == -1 and col ==-1:
        l.append(1)
        print('x')
        print(sudoku)
        return True

    for num in range(1,10):
        if not sudoku.is_conflict(num,row,col):
            sudoku.fill_in_blank(num,row,col)
            sudoku.col_cap[col] += 1
            sudoku.row_cap[row] += 1
            col_cap_max_before = sudoku.col_cap_max
            row_cap_max_before = sudoku.row_cap_max
            if sudoku.col_cap[col] == 9:
                sudoku.col_cap_max = sudoku.max_less_than_nine_col()
            if sudoku.row_cap[row] == 9:
                sudoku.row_cap_max = sudoku.max_less_than_nine_row()
            solve1(sudoku,l)
            sudoku.fill_in_blank(0,row,col)
            sudoku.col_cap[col] -= 1
            sudoku.row_cap[row] -= 1
            if sudoku.col_cap[col] == 8:
                sudoku.col_cap_max = col_cap_max_before
            if sudoku.row_cap[row] == 8:
                sudoku.row_cap_max = row_cap_max_before
    return False



def run():
    su = sudoku()
    su.initialize("sudoku_file.txt")
    l = []
    solve(su,l)
    for s in l:
        print(s)
    print(str(len(l))+" solution(s) generated.")

run()