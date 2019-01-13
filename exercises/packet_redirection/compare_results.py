import sys
from read_fp import P0fDatabaseReader

reader = P0fDatabaseReader()

p4 = []
with open("p4-result.txt") as f:
    for line in f:
        field_list = line.split()
        label_id = field_list[-1]
        if "miss" in label_id:
            p4.append("???")
        else:
            label_id = label_id.split(',')[0]
            label = reader.id_to_label(int(label_id, 16))
            if "???" in label:
                p4.append("???")
            else:
                name = label.split(':')
                p4.append(' '.join(name[2:]).strip())

p0f = []
with open("p0f-result.txt") as f:
    for line in f:
        field_list = line.split("|")
        label = field_list[4].split('=')[1]
        p0f.append(label.strip())
       
diff_count = 0
for i in range(len(p4)):
    if p4[i] != p0f[i]:
        print("p4: {} | p0f: {}".format(p4[i], p0f[i]))
        diff_count += 1

print("diff count: {}".format(diff_count))