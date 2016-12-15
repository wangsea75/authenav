./genkey.sh
./sign_h264_file mos.mp4 mos_signed.mp4 private_key.pem
./verify_h264_file mos_signed.mp4 public_key.pem
