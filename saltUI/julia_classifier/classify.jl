import JSON
using DataFrames
include("scaling.jl")
module EduNets
  include("columnsparsematrix.jl")
  include("superinstance.jl")
  include("linear.jl")
  include("losses.jl")
  include("reluMax.jl")
  include("reluMaxReluMax.jl")
end
# fixing jsons: sed -r -e 's/"tls_osid": ([a-f0-9]+),/"tls_osid": "\1",/' -e 's/"tls_isid": ([a-f0-9]+),/"tls_isid": "\1",/'
# for f in `ls /Data/STLD` ; do 
#   sed -r -e 's/"tls_osid": ([a-f0-9]+),/"tls_osid": "\1",/' -e 's/"tls_isid": ([a-f0-9]+),/"tls_isid": "\1",/' < $f > /home/tomas/data/jsons/${f##*/};
# done

function processfile(filename;maxPacks=20,maxLen=Int64(1e7),maxFlows=Int64(1e6),minflows=0)
  #information for idents
  srcIP=fill("",maxFlows);
  dstIP=fill("",maxFlows);
  ms=fill("",maxFlows);
  ifName=fill("",maxFlows);
  srcPr=zeros(Int32,maxFlows);
  dstPr=zeros(Int32,maxFlows);
  ts=zeros(maxFlows);
  te=zeros(maxFlows);
  index=zeros(Int32,maxFlows);

  #arrays to construct the sparse matrix with features
  I=zeros(Int64,maxLen);
  J=zeros(Int64,maxLen);
  V=zeros(Int64,maxLen);
  packetIdx=1;
  flowIdx=1;
  absoluteindex=1

  D=JSON.parsefile(filename);
  # store counters before processing the file to provide statistics
  startPacketIdx=packetIdx;
  startFlowIdx=flowIdx;
  for appflow in D["appflows"]
    index[flowIdx]=absoluteindex;
    absoluteindex+=1;

    flow=appflow["flow"]
    #some checks to prevent useless work
    if !haskey(flow,"non_norm_stats")
      continue
    end
    if length(flow["non_norm_stats"])==0
      continue
    end

    if haskey(flow,"ts")
      ts[flowIdx]=flow["ts"]
    end
    if haskey(flow,"te")
      te[flowIdx]=flow["te"]
    end
    if haskey(flow,"ms")
      ms[flowIdx]=flow["ms"]
    end
    srcIP[flowIdx]=flow["sa"];
    dstIP[flowIdx]=flow["da"];
    srcPr[flowIdx]=flow["sp"];
    dstPr[flowIdx]=flow["dp"];
    ifName[flowIdx]=filename;

    colIdxO=1
    colIdxI=1
    for d in flow["non_norm_stats"] # array of dict 
      if !(haskey(d,"dir")&&haskey(d,"b")&&haskey(d,"ipt"))
        continue
      end
      if d["dir"] == ">" && colIdxO<2*maxPacks
        I[packetIdx:packetIdx+1]=[flowIdx,flowIdx]
        J[packetIdx:packetIdx+1]=[colIdxO,colIdxO+1]
        V[packetIdx:packetIdx+1]=[d["b"],d["ipt"]]
        colIdxO=colIdxO+2
        packetIdx=packetIdx+2
      end
      if d["dir"] == "<" && colIdxI<2*maxPacks
        # println((d["b"],d["ipt"]))
        I[packetIdx:packetIdx+1]=[flowIdx,flowIdx]
        J[packetIdx:packetIdx+1]=2*maxPacks+[colIdxI,colIdxI+1]
        V[packetIdx:packetIdx+1]=[d["b"],d["ipt"]]
        colIdxI=colIdxI+2
        packetIdx=packetIdx+2
      end
    end
    if colIdxO>1 || colIdxI>1
      flowIdx=flowIdx+1
    end
  end

  #if the sample does not have sufficient numebr of flows, it will be skipped
  if (flowIdx-startFlowIdx<minflows)
    # println("skipping $f since there was only $(flowIdx-startFlowIdx) flows")
    packetIdx=startPacketIdx;
    flowIdx=startFlowIdx;
  else
    # println("from file $filename $(flowIdx-startFlowIdx) flow and $(packetIdx-startPacketIdx) packets")
  end

  (flows,info)=createdata(I,J,V,srcIP,dstIP,ms,ifName,srcPr,dstPr,ts,te,packetIdx,index,flowIdx);
  (bags,subbags,ipofbags)=bagusers(info[:srcIP],info[:dstIP],map(Int64,(floor(info[:ts]/300))))
  ds=EduNets.SuperBagDataSet(flows,-ones(Int,length(bags)),bags,subbags,info)
  return(ds,ipofbags,D["appflows"])
end


function bagusers(srcip,dstip,timestamps)
  #users are bagged based on the type-stamp when the connection has started and user's IP address
  outeripmap=Dict{eltype(dstip),Array{Int64}}()
  for i in 1:length(srcip)
    for ip in [srcip[i],dstip[i]]
      key= @sprintf("%s-%d",ip,timestamps[i])
      if !haskey(outeripmap,key)
        outeripmap[key]=[i]
      else
        push!(outeripmap[key],i)
      end
    end
  end

  #once we have determined the sub-bags, we need to determine subbags and convert the dictionary into array
  subbags=Array{Array{Int64,1},1}(0);
  bags=Array{Array{Int64,1},1}(length(outeripmap));
  ipofbags=Array{eltype(dstip),1}(length(outeripmap));
  bagindex=1;
  for bag in outeripmap
    ip=findhostips(srcip[bag[2]],dstip[bag[2]])
    bagsofbag=Dict{eltype(dstip),Array{Int64}}()
    #iterate over indexes and create bags groupping connections with the same source / destination IP address
    for i in bag[2]
      #determine the remote ip remoteip
      remoteip=(srcip[i]==ip)?dstip[i]:srcip[i];
      #check if there is a bag with such remote ip. if not, create it, otherwise add the index to the subbag
      if !haskey(bagsofbag,remoteip)
        bagsofbag[remoteip]=[i]
      else
        push!(bagsofbag[remoteip],i)
      end
    end

    #add the bag and its subbags to corresponding arrays 
    ipofbags[bagindex]=ip;
    bags[bagindex]=length(subbags)+collect(1:length(bagsofbag));
    append!(subbags,collect(values(bagsofbag)));
    bagindex+=1;
  end
  return(bags,subbags,ipofbags)
end

function createdata(I,J,V,srcIP,dstIP,ms,ifName,srcPr,dstPr,ts,te,packetIdx,index,flowIdx)
  println("parsed $(flowIdx-1) flows and $(packetIdx-1) packets")
  I=I[1:packetIdx-1]
  J=J[1:packetIdx-1]
  V=V[1:packetIdx-1]
  srcIP=srcIP[1:flowIdx-1]
  dstIP=dstIP[1:flowIdx-1]
  ms=ms[1:flowIdx-1]
  ifName=ifName[1:flowIdx-1]
  srcPr=srcPr[1:flowIdx-1]
  dstPr=dstPr[1:flowIdx-1]
  ts=ts[1:flowIdx-1]
  te=te[1:flowIdx-1]
  index=index[1:flowIdx-1]
    #create the data here
  flows=full(sparse(J,I,log(1+V)));
  info=DataFrame(srcIP=srcIP,srcPr=srcPr,dstIP=dstIP,dstPr=dstPr,ts=ts,te=te,ifName=ifName,flowindex=index);
  return(flows,info);
end

""" findhostips(srcips,dstips;check=true)
 Determines quickly set of IP addresses present in all flows. If check is true, the function continues to end. Otherwise it stops when
 there is only one remaining ip address. """
function findhostips(srcips,dstips;check=false)
  #the ip address has to be present in all connections
  r1=sum((srcips[1].==srcips) | (srcips[1].==dstips))
  r2=sum((dstips[1].==srcips) | (dstips[1].==dstips))
  if (check&&(r1<length(srcips)) && (r2<length(dstips)))
    error("IP address not present in all connections")
  end
  ip=(r1>r2)?srcips[1]:dstips[1];
  return ip
end

"""This is used to resolve ties"""
function findhostips(srcip::AbstractString,dstip::AbstractString;check=false)
  println("single")
  return srcip;
end

type DeviceInfo
    ip::ASCIIString;
    output::AbstractFloat;
    label::Int;
    flows::Array{Any,1};
end

function contributors(ifname,ofname;scalefile="reluMaxReluMax_sc.txt",modelfile="reluMaxReluMax_theta.txt",topk=typemax(Int))
  (ds,ipofbags,appflows)=processfile(ifname;maxPacks=20,maxLen=Int64(1e7),maxFlows=Int64(1e6),minflows=0)
  sc=ScalingParams(scalefile);
  scale!(ds.x,sc);

  model=EduNets.ReluMaxReluMaxModel((length(sc.mn),20,20));
  EduNets.update!(model,readdlm(modelfile))

  #do the forward part of the network
  (O2,maxI2)=EduNets.forward(ds.x,model.first,ds.subbags);
  (O1,maxI1)=EduNets.forward(O2,model.second,ds.bags);
  O0=EduNets.forward(O1,model.third);

  #sort the users from the most infected to the least ones
  idxs=sortperm(O0,rev=true);
  if length(idxs)>topk
    idxs=idxs[1:topk]
  end

  deviceinfos=Array{DeviceInfo,1}(0)
  for idx in idxs
    if O0[idx]<=0
      if topk<typemax(Int)
        push!(deviceinfos,DeviceInfo(ipofbags[idx],1.0/(1+exp(-O0[idx])),ds.y[idx],[]))
      end
      continue
    end
    # println("bagid = $idx $(ds.y[idx]) $(O0[idx])")
    #get list of unique domains
    domains=setdiff(unique(maxI1[:,idx]),0);
    domaincontributions=zeros(Float64,length(domains))
    #iterate over domains
    domainweights=zeros(eltype(model.second.W),size(model.second.W,1),length(domains));
    for (index,d) in enumerate(domains)
      #iterate over neurons that had maximum on this domain
      for n in find(d.==domains)
        domainweights[:,index]+=model.third.w[n]*model.second.W[:,n]
        domaincontributions[index]+=model.third.w[n]*O1[n,idx]
      end
    end

    #try to get contributions of individual flows to the domain and output therefor
    triggerflows=Array{Any,1}(0)
    for domainindex in sortperm(domaincontributions,rev=true);
      d=domains[domainindex]
      # println("domain $(d) $(domaincontributions[domainindex])")
      ii2=maxI2[:,d]
      flows=setdiff(unique(ii2),0);
      # print(flows)
      flowcontributions=zeros(Float64,length(flows))
      for (i,flow) in enumerate(flows)
        for fl in find(ii2.==flow)
          flowcontributions[i]+=O2[fl,d]*domainweights[fl,domainindex]
        end
      end
      sorti=sortperm(flowcontributions,rev=true);
      for j in sorti
        flowj=flows[j]
        # if flowcontributions[j]>0
          # println(@sprintf(" %+.2f %s:%d --> %s:%d\t %s",flowcontributions[j],ds.info[flowj,:srcIP],ds.info[flowj,:srcPr],ds.info[flowj,:dstIP],ds.info[flowj,:dstPr],ds.info[flowj,:ifName]))
          # println(@sprintf(" %+.2f %s:%d --> %s:%d",flowcontributions[j],ds.info[flowj,:srcIP],ds.info[flowj,:srcPr],ds.info[flowj,:dstIP],ds.info[flowj,:dstPr]))
          appflows[flowj]["flow"]["contribution"]=flowcontributions[j]
          push!(triggerflows,appflows[flowj]["flow"]);
        # end
      end
    end
    # println()
    push!(deviceinfos,DeviceInfo(ipofbags[idx],1.0/(1+exp(-O0[idx])),ds.y[idx],triggerflows))
  end
  #write the json
  open(ofname,"w") do of
    write(of,JSON.json(deviceinfos))
  end
end

if length(ARGS)<2
  println("usage: julia classify.jl input_json output_json (maximum)");
  println();
else
  topk=typemax(Int)
  if length(ARGS)==3;
    topk=parse(Int,ARGS[3])
  end
  contributors(ARGS[1],ARGS[2];topk=topk)
end
