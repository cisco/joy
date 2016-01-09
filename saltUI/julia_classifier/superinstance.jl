import JSON
using DataFrames
import Base: size,vcat,length
import StatsBase: sample


"""In this dataset sub-bags is an array of arrays. Each array within an array defines indexes in X t, where each element of the master array corresponds to one subBag, 
and the array within holds indexes of instances belonging to the subBag.
 """
type SuperBagDataSet{T<:AbstractFloat}
  x::AbstractArray{T,2};
  y::AbstractArray{Int,1};
  bags::Array{Array{Int,1},1};
  subbags::Array{Array{Int,1},1};

  info::DataFrames.DataFrame;
end

function sort!(ds::SuperBagDataSet,keys...)
  for ki in 1:length(keys)
    k=keys[ki]
    if size(k,1)!=size(ds,1)
      error("length of $(ki)-th key and dataset has to match ")
    end
  end

  function lt(i,j)
    for ki in 1:length(keys)
      k=keys[ki]
      if k[i]<k[j]
        return true;
      end
      if k[i]>k[j]
        return false;
      end
    end
    return false;
  end

  I=sortperm(1:size(ds,1),lt=lt)
  permute!(ds,I)
end

function sort!(ds::SuperBagDataSet,key::Symbol)
  I=sortperm(ds.info[key])
  permute!(ds,I)
end

""" returns a view into the SuperBagDataSet, such that info, X, and Y storages are the same as of the original ds,
  but only indexes of bags and subbags are changed.
  Indexes should contain indexes of bags in ds."""
function subview(ds::SuperBagDataSet,indexes::AbstractArray{Int})
  #first we need to identify which sub-bags will be present in the view
  present=zeros(length(ds.subbags))
  bags=Array{eltype(ds.bags),1}(length(indexes))
  y=zeros(eltype(ds.y),length(indexes))
  subbags=Array{eltype(ds.subbags),1}(0)
  j=1;
  subindexes=1;
  for bg in indexes
    newbag=zeros(length(ds.bags[bg]))
    for (i,sb) in enumerate(ds.bags[bg])
      #this checks, if subbag was already add to the array of subbags. If not, It is added to the container
      # and added to subbags
      if present[sb]==0
        present[sb]=subindexes;
        subindexes=subindexes+1
        push!(subbags,ds.subbags[sb])
      end
      newbag[i]=present[sb]
    end
    bags[j]=newbag
    y[j]=ds.y[bg]
    j+=1;
  end
  return(SuperBagDataSet(ds.x,y,bags,subbags,ds.info))
end

function samplebags(ds::SuperBagDataSet,n::Int64)
  indexes=sample(1:length(ds.bags),n,replace=false)
  return(subview(ds,indexes))
end

function vcat(d1::SuperBagDataSet,d2::SuperBagDataSet)
  #we need to redefine bags and sub-bags, of them needs to be shifted by the number of bags / instances in d1
  bags=deepcopy(d1.bags)
  for bag in d2.bags
    newbag=deepcopy(bag)+length(d1.subbags)
    push!(bags,newbag)
  end

  subbags=deepcopy(d1.subbags)
  for bag in d2.subbags
    newbag=deepcopy(bag)+size(d1.x,2)
    push!(subbags,newbag)
  end

  ds=SuperBagDataSet(hcat(d1.x,d2.x),vcat(d1.y,d2.y),bags,subbags,vcat(d1.info,d2.info));
  return(ds)
end

function size(d::SuperBagDataSet)
  return(length(d.bags),size(d.x,1))
end

function size(ds::SuperBagDataSet,n::Int)
  if n==1
    return length(ds.bags)
  else 
    return size(ds.x,1)
  end
end