
<style type="text/css">
td {
    padding:0 15px 0 15px;
}

th {
    padding:0 15px 0 15px;
}

.divbox {
  border-radius: 15px 50px;
  background: rgb(220, 220, 220);
  padding: 10px;
  margin: 10px;
  margin-top: 20px;
}

</style>
<!--  background: rgb(128, 255, 255); -->

<div class="modal-header">
  <h4 class="modal-title" id="myModalLabel">TLS Fingerprint</h4>
  <button align="right" type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
</div>


<div class="modal-body">

  <div class="divbox">
  <h5 style="text-align:center;text-decoration:underline;">Metadata</h3>
  <table>
    <tbody>
      <tr>
        <td>Source:</td>
        <td>{{fp_['source_addr']}} ({{fp_['source_port']}})</td>
      </tr>
      <tr>
        <td>Destination:</td>
        <td>{{fp_['dest_addr']}} ({{fp_['dest_port']}})</td>
      </tr>
      <tr>
        <td>Timestamp:</td>
        <td>{{fp_['timestamp']}}</td>
      </tr>
      <tr>
        <td style="padding-top:15px">Max Implementation Date:</td>
        <td style="padding-top:15px">{{fp_['fingerprint']['max_implementation_date']}}</td>
      </tr>
      <tr>
        <td>Min Implementation Date:</td>
        <td>{{fp_['fingerprint']['min_implementation_date']}}</td>
      </tr>
    </tbody>
  </table>
  </div>


  <div class="divbox">
  <h5 style="text-align:center;text-decoration:underline;">Probable Applications</h3>
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
    % for i in range(len(fp_['fingerprint']['process_info'])):
      <tr>
        <td>{{fp_['fingerprint']['process_info'][i]['prevalence']}}</td>
        <td>{{fp_['fingerprint']['process_info'][i]['process']}}</td>
        <td>{{fp_['fingerprint']['process_info'][i]['application_category']}}</td>
        <td>{{fp_['fingerprint']['process_info'][i]['sha256']}}</td>
      </tr>
    % end
    </tbody>
  </table>
  </div>


  <div class="divbox">
  <h5 style="text-align:center;text-decoration:underline;">Probable Operating Systems</h3>
  <table>
    <thead>
      <tr>
        <th>Prevalence</th>
        <th>Operating System</th>
        <th>OS Version</th>
        <th>OS Edition</th>
      </tr>
    </thead>
    <tbody>
    % if 'os_info' in fp_['fingerprint']:
      % for i in range(len(fp_['fingerprint']['os_info'])):
        <tr>
          <td>{{fp_['fingerprint']['os_info'][i]['prevalence']}}</td>
          <td>{{fp_['fingerprint']['os_info'][i]['os']}}</td>
          <td>{{fp_['fingerprint']['os_info'][i]['os_version']}}</td>
          <td>{{fp_['fingerprint']['os_info'][i]['os_edition']}}</td>
        </tr>
      % end
    % else:
        <tr>
          <td>Unknown</td>
          <td>Unknown</td>
          <td>Unknown</td>
          <td>Unknown</td>
        </tr>
    % end
    </tbody>
  </table>
  </div>


  <div class="divbox">
  <h5 style="text-align:center;text-decoration:underline;">Cipher Suites</h3>
  <table>
    <thead>
      <tr>
        <th>Strength</th>
        <th>Key Exchange</th>
        <th>Authentication</th>
        <th>Bulk Encryption</th>
        <th>Message Authentication</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
    % for i in range(len(fp_['fingerprint']['tls_features']['cipher_suites'])):
      <tr>
        <td><span style="color:{{fp_['fingerprint']['tls_features']['cs_mapping'][i]['color']}}">{{fp_['fingerprint']['tls_features']['cs_mapping'][i]['strength']}}</span></td>
        <td>{{fp_['fingerprint']['tls_features']['cs_mapping'][i]['kex']}}</td>
        <td>{{fp_['fingerprint']['tls_features']['cs_mapping'][i]['sig']}}</td>
        <td>{{fp_['fingerprint']['tls_features']['cs_mapping'][i]['enc']}}</td>
        <td>{{fp_['fingerprint']['tls_features']['cs_mapping'][i]['hash']}}</td>
        <td>{{fp_['fingerprint']['tls_features']['cipher_suites'][i]}}</td>
      </tr>
    % end
    </tbody>
  </table>
  </div>


  <div class="divbox">
  <h5 style="text-align:center;text-decoration:underline;">Extensions</h3>
  <table>
    <thead>
      <tr>
        <th>Extension Type</th>
        <th>Extension Data</th>
      </tr>
    </thead>
    <tbody>
    % if 'extensions' in fp_['fingerprint']['tls_features']:
      % for i in range(len(fp_['fingerprint']['tls_features']['extensions'])):
        <tr>
          <td>{{fp_['fingerprint']['tls_features']['extensions'][i].keys()[0]}}</td>
          <td></td>
        </tr>
      % end
    % end
    </tbody>
  </table>
  </div>

</div>


<div class="modal-footer">
  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
</div>



