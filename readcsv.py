import csv
import numpy as np

# with open ('soduku.csv', 'r') as csv_file:
#     csv_read = csv.reader(csv_file)
#
    # with open('solving.csv', 'w') as csv_out:
    #     csv_write = csv.writer(csv_out, delimiter='\t')
    #
    #     for line in csv_read:
    #         csv_write.writerow(line)
    #         print(line)
# help(np.loadtxt)
data = np.loadtxt('soduku.csv', dtype="uint8", delimiter=",")
print(data[2,0])