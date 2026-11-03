# CyberDistro Sentinel — Zeek site policy (loaded as "local sentinel").
# JSON logs (read by sentinel-core) and short rotation so logs stay small on the
# RAM overlay of a live system. Rotated files are deleted by the postprocessor:
# incidents and their evidence pointers are already in the Sentinel database.
@load tuning/json-logs

redef Log::default_rotation_interval = 15 min;
redef Log::default_rotation_postprocessor_cmd = "/usr/local/sbin/sentinel-zeek-rotated";

# We only read packets; never write extracted files to disk.
redef ignore_checksums = T;
