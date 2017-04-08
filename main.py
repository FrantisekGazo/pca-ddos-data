#!/usr/bin/python

import csv

###########################################################################
#
# Dataset from:
# https://www.researchgate.net/publication/292967044_Dataset-_Detecting_Distributed_Denial_of_Service_Attacks_Using_Data_Mining_Techniques
#
###########################################################################

PKT_TYPE = ['tcp', 'ack', 'cbr', 'ping']
PKT_TYPE_INDEX = 5
FLAGS = ['-------', '---A---']
FLAGS_INDEX = 7
NODE_NAME_FROM = ['Switch1', 'Router', 'server1', 'router', 'clien-4', 'client-2', 'Switch2', 'client-5', 'clien-9',
                  'clien-2', 'clien-1', 'clien-14', 'clien-5', 'clien-11', 'clien-13', 'clien-0', 'switch1', 'client-4',
                  'clienthttp', 'clien-7', 'clien-19', 'client-14', 'clien-12', 'clien-8', 'clien-15',
                  'webserverlistin', 'client-18', 'client-1', 'switch2', 'clien-6', 'client-10', 'client-7', 'webcache',
                  'clien-10', 'client-15', 'clien-3', 'client-17', 'client-16', 'clien-17', 'clien-18', 'client-12',
                  'client-8', 'client-0', 'clien-16', 'client-13', 'client-11', 'client-6', 'client-3', 'client-9',
                  'client-19', 'http_client']
NODE_NAME_FROM_INDEX = 12
NODE_NAME_TO = ['Router', 'server1', 'Switch2', 'Switch1', 'clien-1', 'clien-5', 'clien-7', 'switch1', 'clien-11',
                'clien-15', 'clien-13', 'clien-3', 'clien-9', 'clien-6', 'router', 'clien-4', 'clien-14', 'switch2',
                'clien-8', 'clienthttp', 'webcache', 'clien-10', 'clien-12', 'webserverlistin', 'clien-0', 'clien-2',
                'http_client', 'client-13', 'client-9', 'client-1', 'client-19', 'client-4', 'client-17', 'client-7',
                'client-3', 'client-12', 'client-2', 'clien-18', 'client-16', 'clien-17', 'client-0', 'clien-16',
                'client-18', 'client-5', 'client-11', 'client-14', 'client-8', 'client-6', 'client-10', 'clien-19',
                'client-15']
NODE_NAME_TO_INDEX = 13
PKT_CLASS = ['Normal', 'UDP-Flood', 'Smurf', 'SIDDOS', 'HTTP-FLOOD']
PKT_CLASS_INDEX = 27
NON_NUMERIC_FIELDS = {
    PKT_TYPE_INDEX: PKT_TYPE,
    FLAGS_INDEX: FLAGS,
    NODE_NAME_FROM_INDEX: NODE_NAME_FROM,
    NODE_NAME_TO_INDEX: NODE_NAME_TO,
    PKT_CLASS_INDEX: PKT_CLASS
}

IN_FILE_PATH = 'in/in-headless.txt'
OUT_FILE_PATH = 'out/out-{pkt_class}.txt'
IN_CSV_DELIMITER = ','
OUT_CSV_DELIMITER = ' '

MAX_OUT = 500


def clean_row(row):
    new_row = []

    i = 0
    for value in row:
        if i in NON_NUMERIC_FIELDS:
            new_row.append(NON_NUMERIC_FIELDS[i].index(value))
        else:
            new_row.append(float(value))
        i += 1

    return new_row


def process_file(file_path):
    in_file = open(file_path, 'rU')
    csv_reader = csv.reader(in_file, delimiter=IN_CSV_DELIMITER)

    out_files = {}
    csv_writers = {}
    out_i = {}
    for pkt_class in PKT_CLASS:
        out_files[pkt_class] = open(OUT_FILE_PATH.format(pkt_class=pkt_class), 'w+')
        csv_writers[pkt_class] = csv.writer(out_files[pkt_class], delimiter=OUT_CSV_DELIMITER)
        out_i[pkt_class] = 0

    in_i = 0
    for row in csv_reader:
        in_i += 1
        if in_i % 100000 == 0:
            print 'line', in_i

        if not row:
            continue

        pkt_class = row[-1]

        if out_i[pkt_class] >= MAX_OUT:
            continue

        out_i[pkt_class] += 1

        del row[-1]
        cleaned_row = clean_row(row)
        csv_writers[pkt_class].writerow(cleaned_row)

        # end if all out files are full
        end = True
        for pkt_class in PKT_CLASS:
            if out_i[pkt_class] < MAX_OUT:
                end = False
        if end:
            break


def main():
    process_file(IN_FILE_PATH)


if __name__ == '__main__':
    main()
