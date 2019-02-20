if [ $(whoami) = "root" ]; then
    apt install -y libpcap-dev
fi

cd $1 ; ./configure
