
'''
Run inside "create_training_data"
'''

import os
from scapy.all import PcapReader, PcapWriter


raw_dir = "raw_data"
train_dir = "training_data"
val_dir = "validation_data"

split_ratio = 0.85

os.makedirs(train_dir, exist_ok=True)
os.makedirs(val_dir, exist_ok=True)

# !!!   important to check that there is no data in dirs
#       to not overwrite already labeled data
assert not any(f.endswith(".pcap") for f in os.listdir(train_dir)), \
        "train_data already contains .pcap files"

assert not any(f.endswith(".pcap") for f in os.listdir(val_dir)), \
        "validation_data already contains .pcap files"

pcap_files = [f for f in os.listdir(raw_dir) if f.endswith(".pcap")]
assert pcap_files, "No PCAP files found"

for pcap_name in pcap_files:
    print(f"Processing {pcap_name}")
    pcap_path = os.path.join(raw_dir, pcap_name)

    # first pass, collect timestamps
    timestapms = []
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if hasattr(pkt, "time"):
                timestapms.append(pkt.time)
    
    t_start = timestapms[0]
    t_end = timestapms[-1]
    duration = t_end - t_start

    print(f"Duration: {duration:.2f} seconds")

    split_time = t_start + duration * split_ratio

    # second pass, split into train and validation  

    data_name, ext = os.path.splitext(pcap_name)
    train_file_name = data_name + "_train" + ext
    val_file_name = data_name + "_val" + ext

    train_writer = PcapWriter(
        os.path.join(train_dir, train_file_name), append=False, sync=True
    )
    val_writer = PcapWriter(
        os.path.join(val_dir, val_file_name), append=False, sync=True
    )

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if pkt.time <= split_time:
                train_writer.write(pkt)
            else:
                val_writer.write(pkt)

    train_writer.close()
    val_writer.close()

