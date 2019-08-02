import numpy as np

zero_arr = np.zeros (9, dtype="uint8")        # used to turn bool to 1 for true
one_arr = np.ones (9, dtype="uint8")        # used to turn bool to 1 for true
solving = np.zeros([9,9,9], dtype="uint8")    # each row is possible numbers in a square - L to R, top to bottom
filled_cell = np.zeros([9,9], dtype="uint8")

puzzle = np.loadtxt('soduku_easy.csv', dtype="uint8", delimiter=",")
# print(puzzle)
# tmp = puzzle[0] == 3
# solv_3 = tmp+zero_arr
x=0
while x <= 8: # loop to move through lines in the puzzle array and create solving and filled_cell arrays
    y=0
    while y <= 8: # loop to test for each number
        solving[x, y, :] = zero_arr
        z=y+1
        tmp = puzzle[x] == z
        # print (tmp)
        if True in tmp:
            is_it = one_arr
        else:
            is_it = zero_arr
        # tmp = zero_arr + tmp
        # print(x, z, tmp)
        # print(x, z, is_it)

        solving[x, y, :] = (solving[x, y, :] + is_it)
        filled_cell[x, :] = (filled_cell[x, :] + tmp)
        y += 1
    x += 1
# print (solving)
# print (solving[0,:,0])
# print (filled_cell)
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
                # print(x,y,puzzle[x,y])
                # print(puzzle)
        y += 1
    x += 1

print(puzzle)

# this loop is solving for each sub cell of 9
x = 0
while x <= 8:  # loop to find and mark solved numbers in the puzzle
    y = 0
    while y <= 8:
        # print(puzzle[x,y])
        if puzzle[x, y] == 0:
            # print(solving[x, :, y])
            tmp = np.sum(solving[x, :, y])

            if tmp == 8:
                dam = solving[x, :, y]
                damit = np.ndarray.tolist(dam)
                dammitt = damit.index(0) + 1
                # print(dammitt)
                puzzle[x, y] = (dammitt)
                # print(x,y,puzzle[x,y])
                # print(puzzle)
        y += 1
    x += 1

# print (solving)
# print (np.size(solving))
# print(filled_cell)

# # print(puzzle[0:0, 2:2])
# print(puzzle[0])
# print(puzzle[:,0])
# print(puzzle[0] == 3)



# ------ second try ------
# columns = [0, 1, 2, 3, 4, 5, 6, 7, 8]
# dict = {}
# col_out = []
# x=0
# while x <= 8:
#     key=("col" + str(x))
#     # name = "col" + str(x)
#     name = puzzle[[0, 1, 2, 3, 4, 5, 6, 7, 8], [x, x, x, x, x, x, x, x, x]]
#     out = [key, name]
#     col_out = col_out + out
#     x += 1
# # print (out[0], out[1])
# print (col_out)

# ------ first try ------
# rows = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8], dtype=np.uint)
# cols = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8], dtype=np.uint)
# print(puzzle[rows[:, np.newaxis], cols])

# actual_col1 = np.array([[0,0], [1,0], [2,0], [3,0], [4,0], [5,0], [6,0], [7,0], [8,0]], dtype=np.uint)
# actual_col1 = np.array([[0,0], [1,0], [2,0]], dtype=np.uint)
# print(puzzle[actual_col1])


# x = np.array([[[1,9,8],[2,7,6],[3,5,4]], [[4,10,11],[5,12,13],[6,14,15]]])
# x = np.array([[1,9,8],[2,7,6],[3,5,4]])
# print(x[[0, 1, 2], [0, 0, 0]])
# rows = np.array([[0, 0], [1, 1], [2, 2]], dtype=np.uint)
# cols = np.array([[0, 0], [1, 1], [2, 2]], dtype=np.uint)
# print(x[rows])