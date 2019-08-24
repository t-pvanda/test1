import numpy as np

zero_arr = np.zeros (9, dtype="uint8")        # used to turn bool to 1 for true
one_arr = np.ones (9, dtype="uint8")        # used to turn bool to 1 for true
solving = np.zeros([9,9,9], dtype="uint8")    # each row is possible numbers in a square - L to R, top to bottom
filled_cell = np.zeros([9,9], dtype="uint8")

puzzle = np.loadtxt('soduku_easy.csv', dtype="uint8", delimiter=",")

x=0
while x <= 8: # loop to move through lines in the puzzle array and create solving and filled_cell arrays
    y=0
    while y <= 8: # loop to test for each number
        solving[x, y, :] = zero_arr
        z = y + 1
        tmp = puzzle[x] == z
        # print (tmp)
        if True in tmp:
            is_it = one_arr # one array marks this number as not existing in the cell
        else:
            is_it = zero_arr
        # tmp = zero_arr + tmp
        # print(x, z, tmp)
        # print(x, z, is_it)

        solving[x, y, :] = (solving[x, y, :] + is_it)
        filled_cell[x, :] = (filled_cell[x, :] + tmp)
        # print (puzzle[x,y])
        # print (filled_cell[x, :])
        y += 1
    x += 1
# print (solving)
# print (solving[0,:,0])
# print (filled_cell[:,0])

x=0
while x <= 8: # checking column matches
    y=0
    while y <= 8: # loop to check each cell
        z=0
        while z <= 8: # loop to check each number in the column and mark it out
            number = z+1
            # print (filled_cell[z,y])
            if puzzle[z,y] > 0:
                tmp = puzzle[z,y]
                tmp = tmp-1
                # print (x,tmp,y)
                solving[x,tmp,y] = 1
                # print (solving[z,y,tmp])
            z += 1
        y += 1
    x += 1

# print (solving)

def line_func (puzzle):
    # this loop is solving for rows and columns
    x=0
    while x <= 8: # loop to find and mark solved numbers in the puzzle
        y=0
        while y <= 8:
            # print(puzzle[x,y])
            if puzzle[x,y] == 0:
                # print(solving[x, :, y])
                tmp = np.sum(solving[x, :, y])

                if tmp == 8:
                    dam = solving[x,:,y]
                    damit = np.ndarray.tolist(dam)
                    dammitt = damit.index(0)+1
                    # print(dammitt)
                    puzzle[x,y] = (dammitt)
                    filled_cell[x, y] = 1
                    # print(x,y,puzzle[x,y])
                    # print(puzzle)
            y += 1
        x += 1
    return (puzzle)

print (puzzle)
# print (filled_cell)

def block_func (puzzle):
    # this loop is solving for each sub cell of 9
    for index in [0,3,6]:
        subcellsum = 0
        tmp = 0
        x=0
        while x <= 8:
            y= 0+index
            while y <= 2+index: # loop to check each subcell of 9
                tmp = tmp + filled_cell[x, y]
                subcellsum = (subcellsum + (puzzle[x, y]))
                # print (subcellsum, x, y)
                if filled_cell[x, y] == 0:
                    emptyx = x
                    emptyy = y
                y += 1
            x += 1
            if not (x % 3):
                if tmp == 8:
                    # print(emptyx, emptyy, subcellsum)
                    cellfillvalue = 45 - subcellsum
                    puzzle[emptyx, emptyy] = cellfillvalue
                    filled_cell[emptyx, emptyy] = 1
                subcellsum = 0
                tmp = 0
    return (puzzle)

line_func(puzzle)
block_func(puzzle)
line_func(puzzle)
block_func(puzzle)

# print(filled_cell)
print (puzzle)
# print (solving)
# print (np.size(solving))
# print(filled_cell)