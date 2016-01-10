import Base.LinAlg.scale!,Base.LinAlg.scale;

type ScalingParams
    mn::Vector #this will be subtracted
    sd::Vector #this will be the divisiaon
end

function ScalingParams(x,option="domain";tol=1e-6)
    if option=="domain"
        mn=squeeze(minimum(x,2),2);
        mx=squeeze(maximum(x,2),2);
        sd=mx-mn;
    end
    if option=="variance"
        mn=squeeze(mean(x,2),2);
        sd=squeeze(std(x,2),2);
    end
    
    i=findn(sd.>tol);
    sd[i]=1./sd[i];
    return ScalingParams(mn,sd)
end

function scale(x,sc::ScalingParams)
    if size(x,1)!=length(sc.mn)
        error("scale: Scaling parameters and x have different dimensions")
    end
    y=broadcast(-,x,sc.mn)
    broadcast!(*,y,y,sc.sd)
    return(y)
end

function scale!(x,sc::ScalingParams)
    if size(x,1)!=length(sc.mn)
        error("scale: Scaling parameters and x have different dimensions")
    end
    broadcast!(-,x,x,sc.mn)
    broadcast!(*,x,x,sc.sd)
end

function ScalingParams(filename::ASCIIString)
    s=readdlm(filename);
    return(ScalingParams(s[:,1],s[:,2]));
end
