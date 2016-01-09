import Base.length;

export ReluMaxReluMaxModel, update!,model2vector,forward,gradient,trainReluMaxReluMax;

type ReluMaxReluMaxModel{T<:AbstractFloat}
    first::ReluMaxModel{T};
    second::ReluMaxModel{T};
    third::LinearModel{T};
end

function ReluMaxReluMaxModel(theta::AbstractArray,k::Tuple{Int,Int,Int})
    model=ReluMaxReluMaxModel(k);
    update!(model,theta);
    return(model);
end

function ReluMaxReluMaxModel(k::Tuple{Int,Int,Int})
    return(ReluMaxReluMaxModel(ReluMaxModel(k[1],k[2]),ReluMaxModel(k[2],k[3]),LinearModel(k[3])))
end

function update!{T}(model::ReluMaxReluMaxModel{T},theta::AbstractArray{T})
    ends=cumsum([0,length(model.first),length(model.second),length(model.third)])
    update!(model.first,theta[ends[1]+1:ends[2]])
    update!(model.second,theta[ends[2]+1:ends[3]])
    update!(model.third,theta[ends[3]+1:ends[4]])
end

function model2vector(model::ReluMaxReluMaxModel)
    vcat(model2vector(model.first),model2vector(model.second),model2vector(model.third))
end

""" forward{T}(ds::SuperBagDataSet{T},model::ReluMaxReluMaxModel{T}) """
function forward{T}(ds::SuperBagDataSet{T},model::ReluMaxReluMaxModel{T})
    #do the forward propagation
    (O2,_)=forward(ds.x,model.first,ds.subbags);
    (O1,_)=forward(O2,model.second,ds.bags);
    O0=forward(O1,model.third);
    return(O0)
end

""" reluMaxReluMaxErr(ds::SuperBagDataSet{T},theta::AbstractArray{T,1},k::Tuple{Int,Int,Int})
Returns error on bags of the network calculated by the hinge loss."""
function loss{T}(ds::SuperBagDataSet{T},model::ReluMaxReluMaxModel{T})
    O0=forward(ds,model)
    f=hingeLoss(O0,ds.y);
    return(f)
end

""" reluMaxReluMaxErrG{T}(ds::SuperBagDataSet{T},theta::AbstractArray{T,1},k::Tuple{Int,Int,Int})
Returns tuple (f,gW2,gB2,gW1,gB1,gW0,gB0), where f is the error of the network calculated by the hinge loss, and the rest are gradients."""
function gradient(ds::SuperBagDataSet,model::ReluMaxReluMaxModel)
    #some conversion of parameters and allocation of space for the gradient
    (O2,maxI2)=forward(ds.x,model.first,ds.subbags);
    (O1,maxI1)=forward(O2,model.second,ds.bags);
    O0=forward(O1,model.third);

    (f,gF)=hingeLossG(O0,ds.y);
    #derivative of the output linear unit
    (g3,gO0)=backprops(O1,model.third,gF)
    (g2,gO1)=backprops(O2,model.second,gO0,maxI1);
    g1=gradient(ds.x,model.first,gO1,maxI2);
    return(f,ReluMaxReluMaxModel(g1,g2,g3))
end


function trainReluMaxReluMax{T}(ds::EduNets.SuperBagDataSet{T},k::Tuple{Int,Int};options=AdamOptions())
    theta=model2vector(ReluMaxReluMaxModel((size(X,1),k...)))
    bagIDs=(find(ds.y.==-1),find(ds.y.==+1))
    theta=adam((x,ids)->reluMaxReluMaxErrG(subview(ds,ids),ReluMaxReluMaxModel(x,k)),theta,bagIDs,options)
    return(ReluMaxReluMaxModel(theta,k))
end
