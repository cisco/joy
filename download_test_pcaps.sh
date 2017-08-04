#!/bin/bash

# Download pcaps from www.pcapr.net. The pcap ids can be found by selecting
# 'protocols' from the top bar of www.pcapr.net, selecting the relevant
# protocol name, and then inspecting the page source with the Chrome browser.

if [ -z $1 ]; then
    echo "USAGE: $0 <test_pcap_dir>"
    exit
fi

username=luke.valenta@gmail.com
password=XcxjLwagnKRYF2ACZ2Q6
pcapdir=$1

ssh_ids="
    27a0080bc259e9b7ed88f80b4368b6df
    3ca92db8389f36a2b1983b4fb939be5d
    485772f7a42894de6e779ca5dd958562
    80998f4345dea2ef46d847841f3b7327
    92671c9edb695af4e57d036343cdbedc
    a094700d574dcffa258c2ba19731440a
    b0a3b649e6b3b37ecc9115b58b96beb6
    b7242fd1a6fc266c09c3a222bad195c5
    c20514974d5d2fcac58087f046dd983d
    d091e2965994724eb310b3e998bbf00d
    d1e33523a8ccaf659e4c03b9f3c693a3
    ddc3b761ea918108ed8d64abeaa19d4a
    de357768a89f57c30428f7c3ee4b488e
"

tls_ids="
    025dcad88b83ccd6b1dd74b8d377895e
    0f0aae61c44e78f41dbb85a5b68ba9b2
    205f07b5a22f93ae144a19faea5e5d55
    25f6fdee7a2b7f41366c48bc210bd634
    262dd727a1a406db7ee7ccac389201d1
    2cc5886af7dda1c28c4e50b4f2bb9a77
    342496eab4a89a914a07312a2b57d75d
    38e49a476ce14faf3876ecd84915c803
    4450959233ec05524f8b0d3893929633
    4ff360305f07ac7fce7522cd64548cf5
    58768beb0032ffa76f1ba7134ac0a7d5
    76fd0570a5278e11724a25eacdc39136
    8e520af6c793463d4449f5c5dc2f4b4e
    8f36c6ef69490e804d623f4db99b2bb7
    a0683d8119eb000ef15fa89ca715b2e9
    bb4dfea5362ed5fa898516e325bf51d2
    c24e0624938d3b1acb004a071b4e168f
    f16b13fe9af94154d682aad0ae1163be
    f4288b3792622eb1338e9a2be5ae8013
    f54be5787808b0ef10472bf037852f22
    fcf108bd8cb63fa1fa14ffba00586198
"

# These pcaps throw lots of errors in wireshark: 
# 530c0dea9e2cdf0c091b5c77e4e70afc
# 5670b222406f2831dac227a46fd0e1f1
# fccafcd194d6c47a1019fefe8e90950a

mkdir -p $pcapdir/ssh
for id in $ssh_ids
do
    filename=$pcapdir/ssh/$id.pcap
    if [ ! -f $filename ]; then
        curl --basic -u $username:$password http://www.pcapr.net/api/download?id=$id > $filename
    fi
done

mkdir -p $pcapdir/tls
for id in $tls_ids
do
    filename=$pcapdir/tls/$id.pcap
    if [ ! -f $filename ]; then
        curl --basic -u $username:$password http://www.pcapr.net/api/download?id=$id > $filename
    fi
done
