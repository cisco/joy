
<style type="text/css">
td {
    padding:0 15px 0 15px;
}

th {
    padding:0 15px 0 15px;
}
</style>

<div class="modal-header">
  <h4 class="modal-title" id="myModalLabel">TLS Fingerprint</h4>
  <button align="right" type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
</div>


<div class="modal-body">
  <h5 style="text-align:center;text-decoration:underline;padding-top:30px;">Application Inventory</h3>
  <table>
    <thead>
      <tr>
        <th>Prevalence</th>
        <th>Process Name</th>
        <th>Application Category</th>
        <th>SHA-256</th>
      </tr>
    </thead>
    <tbody>
    % for i in range(len(client_info)):
      <tr>
        <td>{{client_info[i][0]}}</td>
        <td>{{client_info[i][1]}}</td>
        <td>{{client_info[i][2]}}</td>
        <td>{{client_info[i][3]}}</td>
      </tr>
    % end
    </tbody>
  </table>

</div>


<div class="modal-footer">
  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
</div>



