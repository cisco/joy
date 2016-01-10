import Base.length,Base.LinAlg.gradient;

export ReluMaxModel,length,size,model2vector,update!,forward,forwardrnd,backprops,backprop,gradient

type ReluMaxModel{T<:AbstractFloat}
    W::Array{T,2};
    B::Array{T,1};
end

function ReluMaxModel(d::Int,k::Int)
    return(ReluMaxModel(randn(d,k),randn(k)));
end

function length(model::ReluMaxModel)
    return(length(model.W)+length(model.B))
end

function size(model::ReluMaxModel)
    return((size(model.W,1)+1,model.B));
end

function model2vector(model::ReluMaxModel)
  theta=zeros(eltype(model.W),length(model.W)+length(model.B));
  theta[1:length(model.W)]=model.W;
  theta[length(model.W)+1:end]=model.B;
  return(theta);
end

function update!{T}(model::ReluMaxModel{T},theta::AbstractArray{T})
    model.W=reshape(theta[1:length(model.W)],size(model.W));
    model.B=theta[length(model.W)+1:length(theta)];
end



""" forward{T<:AbstractFloat}((X::SparseMatrixCSC{T,Int64},model::ReluMaxModel,bags::AbstractArray{AbstractArray{Int64,1},1})
    bags identifies bags within the X matrix. Each bag contains array of indexes into x. The indexes does not needs to be continuous, which is the 
    advantage, but it is less efficient than the version with continuous blocks,
    W,B are weight matrix parametrising the relu
    returns tuple (O,maxI) with O being the output of the relus on bags, and maxI being indexes of winners inside the relu.
"""
function forward{T<:AbstractFloat}(X::SparseMatrixCSC{T,Int64},model::ReluMaxModel,bags::Array{Array{Int64,1},1}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    O=zeros(T,size(model.W,2),length(bags))
    maxI=zeros(Int64,size(model.W,2),length(bags))
    for i in 1:length(bags) #iterate over bags
        for j in bags[i]  #iterate over subbags
            xxindexes=X.colptr[j]:(X.colptr[j+1]-1);
            nnzrow=X.rowval[xxindexes];
            nnzval=X.nzval[xxindexes];
            for k in 1:size(model.W,2) #iterate over neurons
                oo=LinAlg.dot(nnzval,model.W[nnzrow,k])+model.B[k]
                if oo>O[k,i]
                    O[k,i]=oo;
                    maxI[k,i]=j;
                end
            end
        end
    end
    return(O,maxI)
end

""" reluMax{T<:AbstractFloat}(X::AbstractArray{T,2},model::ReluMaxModel,bags::AbstractArray{AbstractArray{Int64,1},1})
    bags identifies bags within the X matrix. Each bag contains array of indexes into x. The indexes does not needs to be continuous, which is the 
    advantage, but it is less efficient than the version with continuous blocks,
    W,B are weight matrix parametrising the relu
    returns tuple (O,maxI) with O being the output of the relus on bags, and maxI being indexes of winners inside the relu.
"""
function forward{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,bags::Array{Array{Int64,1},1}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    n=size(model.W,2);
    O=zeros(T,n,length(bags))
    maxI=zeros(Int64,n,length(bags))
    for i in 1:length(bags) #iterate over bags
        for j in bags[i]  #iterate over subbags
            for k in 1:n #iterate over neurons
                oo=model.B[k]
                @simd for l in 1:size(X,1)
                    oo+=X[l,j]*model.W[l,k]
                end
                if oo>O[k,i]
                    O[k,i]=oo;
                    maxI[k,i]=j;
                end
            end
        end
    end
    return(O,maxI)
end

""" reluMax{T<:AbstractFloat}(X::AbstractArray{T,2},model::ReluMaxModel,bags::AbstractArray{AbstractArray{Int64,1},1})
    bags identifies bags within the X matrix. Each bag contains array of indexes into x. The indexes does not needs to be continuous, which is the 
    advantage, but it is less efficient than the version with continuous blocks,
    W,B are weight matrix parametrising the relu
    returns tuple (O,maxI) with O being the output of the relus on bags, and maxI being indexes of winners inside the relu.
"""
function forwardrnd{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,bags::Array{Array{Int64,1},1}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    n=size(model.W,2);
    O=zeros(T,n,length(bags))
    maxI=zeros(Int64,n,length(bags))
    for i in 1:length(bags) #iterate over bags
        smpsize=Int(round(0.05*length(bags[i])));
        smpsize=(smpsize>1)?smpsize:1;
        for j in sample(bags[i],smpsize)  #iterate over subbags
            for k in 1:n #iterate over neurons
                oo=model.B[k]
                @simd for l in 1:size(X,1)
                    oo+=X[l,j]*model.W[l,k]
                end
                if oo>O[k,i]
                    O[k,i]=oo;
                    maxI[k,i]=j;
                end
            end
        end
    end
    return(O,maxI)
end

function backprops{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,gO::AbstractArray{T,2},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    gW=zeros(T,size(model.W))
    gB=zeros(T,length(model.B))
    if isempty(gO) || isempty(maxI)
        return(ReluMaxModel(gW,gB),ColumnSparseMatrix(Array{T,2}(0,0),Array{Int}(0)))
    end

    #calculate the space we will need to store the outputs
    l=length(setdiff(unique(maxI),0));
    gX=zeros(T,size(X,1),l);
    colidxs=Array(Int,l);
    xidxs=sortperm(reshape(maxI,length(maxI)));
    #skip the zeros
    idx=1;
    while idx<=length(maxI) && maxI[xidxs[idx]]==0 
        idx+=1;
    end

    #case if all elements are zeros
    if idx>length(maxI)
        return(ReluMaxModel(gW,gB),ColumnSparseMatrix(Array{T,2}(0,0),Array{Int}(0)))
    end

    #now move to calculate the non-zero gradients
    gxidx=1;
    lastidx=maxI[xidxs[idx]];
    colidxs[gxidx]=maxI[xidxs[idx]];
    # @acc begin
        for ii in idx:length(xidxs)
            #transform linear index into the matrix indexing
            w=(xidxs[ii]-1)%size(model.W,2)+1
            i=Int(floor((xidxs[ii]-w)/size(maxI,1)))+1;

            # check that the input gradient is non-zero 
            if abs(gO[w,i])==0
                continue
            end

            # verify if a gradient to new input vector has appeared
            if lastidx!=maxI[xidxs[ii]]
                gxidx+=1;
                lastidx=maxI[xidxs[ii]];
                colidxs[gxidx]=maxI[xidxs[ii]];
            end

            #update the gradient
            gX[:,gxidx]+=gO[w,i]*slice(model.W,:,w);    
            gB[w]+=gO[w,i];
            gW[:,w]+=gO[w,i]*slice(X,:,maxI[w,i]); # LinAlg.BLAS.blascopy!
        end
    # end

    return(ReluMaxModel(gW,gB),ColumnSparseMatrix(gX[:,1:gxidx],colidxs[1:gxidx]))
end

function backprops{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,gO::ColumnSparseMatrix{T},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    return(backprops(X,model,gO.x,sub(maxI,:,gO.columnindexes)));
end


function backprop{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,gO::AbstractArray{T,2},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    gW=zeros(T,size(model.W))
    gB=zeros(T,length(model.B))
    gX=zeros(T,size(X));
    if isempty(gO) || isempty(maxI)
        return(ReluMaxModel(gW,gB),gX)
    end
    # @acc begin
        for i in 1:size(maxI,2)
            for w in 1:size(model.W,2)
                if maxI[w,i]>0 && abs(gO[w,i])>0
                    gX[:,maxI[w,i]]+=gO[w,i]*slice(model.W,:,w);    
                    gB[w]+=gO[w,i];
                    gW[:,w]+=gO[w,i]*slice(X,:,maxI[w,i]); # LinAlg.BLAS.blascopy!
                end
            end 
        end
    # end
    return(ReluMaxModel(gW,gB),gX)
end

function backprop{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,gO::ColumnSparseMatrix{T},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    return(backprop(X,model,gO.x,sub(maxI,:,gO.columnindexes)));
end

function gradient{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,gO::ColumnSparseMatrix{T},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    return(gradient(X,model,gO.x,sub(maxI,:,gO.columnindexes)));
end

function gradient{T<:AbstractFloat}(X::Array{T,2},model::ReluMaxModel,gO::AbstractArray{T,2},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    gW=zeros(T,size(model.W))
    gB=zeros(T,length(model.B))
    # @acc begin
        for i in 1:size(maxI,2)
            for w in 1:size(model.W,2)
                if maxI[w,i]>0 && abs(gO[w,i])>0   
                    gB[w]+=gO[w,i];
                    gW[:,w]+=gO[w,i]*slice(X,:,maxI[w,i]); # LinAlg.BLAS.blascopy!
                end
            end 
        end
    # end
    return(ReluMaxModel(gW,gB))
end



function gradient{T<:AbstractFloat}(X::SparseMatrixCSC{T,Int64},model::ReluMaxModel,gO::AbstractArray{T,2},maxI::AbstractArray{Int64}) # 0.008853 seconds (152.04 k allocations: 4.354 MB)
    #iterate over bags and biases
    gW=zeros(T,size(model.W))
    gB=zeros(T,size(model.B))
    # @acc begin
        for i in 1:size(maxI,2)
            for w in 1:size(model.W,2)
                if maxI[w,i]>0 && abs(gO[w,i])>0   
                    gB[w]+=gO[w,i];
                    xxindexes=X.colptr[maxI[w,i]]:(X.colptr[maxI[w,i]+1]-1);
                    gW[X.rowval[xxindexes],:]+=gO[w,i]*X.nzval[xxindexes]; # LinAlg.BLAS.blascopy!
                end
            end 
        end
    # end
    return(ReluMaxModel(gW,gB))
end