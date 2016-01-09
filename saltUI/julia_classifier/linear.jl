import Base.length;

export LinearModel,length,size,model2vector,update!,forward,backprops,backprop,gradient

type LinearModel{T<:AbstractFloat}
    w::Array{T,1};
    b::T;
end

function LinearModel(k::Int)
  return(LinearModel(randn(k),randn()));
end

function model2vector(model::LinearModel)
  theta=zeros(eltype(model.w),length(model.w)+length(model.b));
  theta[1:end-1]=model.w;
  theta[end]=model.b;
  return(theta);
end

function update!{T}(model::LinearModel{T},theta::AbstractArray{T})
  model.w=theta[1:end-1];
  model.b=theta[end];
end


function length(model::LinearModel)
    return(length(model.w)+1)
end

function size(model::LinearModel)
    return((size(model.w,1)+1,));
end



function forward{T}(X::AbstractArray{T,2},model::LinearModel{T})
  return(squeeze(model.w'*X+model.b,1))
end


function backprop{T}(X::AbstractArray{T,2},model::LinearModel{T},gO::AbstractArray{T,1})
  gX=model.w*gO';
  gW=X*gO;
  gB=sum(gO);
  return(LinearModel{T}(gW,gB),gX)
end

function backprops{T}(X::AbstractArray{T,2},model::LinearModel{T},gO::AbstractArray{T,1})
  nz0=find(gO);
  gO=gO[nz0];
  gX=model.w*gO';
  gW=X[:,nz0]*gO;
  gB=sum(gO);
  return(LinearModel{T}(gW,gB),ColumnSparseMatrix(gX,nz0))
end


function gradient{T}(X::AbstractArray{T,2},model::LinearModel{T},gO::AbstractArray{T,1})
  gW=X*gO;
  gB=sum(gO);
  return(LinearModel{T}(gW,gB))
end