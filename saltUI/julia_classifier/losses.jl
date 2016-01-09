export hingeLoss,hingeLossG
import Base.LinAlg.gradient;

function hingeLoss(X::Vector,Y::Vector)
  Y=2*(Y-1)-1;
  O=1-Y.*X;
  mask=O.<0;
  O[mask]=0;
  return(mean(O));
end

function hingeLossG(X::Vector,Y::Vector)
  Y=2*(Y-1)-1;
  O=1-Y.*X;
  mask=O.<0;
  O[mask]=0;
  f=mean(O);
  g=-Y/length(Y);
  g[mask]=0;
  return (f,g)
end