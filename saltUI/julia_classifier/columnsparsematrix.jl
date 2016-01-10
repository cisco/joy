type ColumnSparseMatrix{T}
    x::AbstractArray{T,2};
    columnindexes::AbstractArray{Int,1};
end