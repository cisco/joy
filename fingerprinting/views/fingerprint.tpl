
% rebase('base.tpl', title='Fingerprinting Results')

<script src="https://code.jquery.com/jquery-2.1.4.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.js"></script>


<style>
.modal-xl {
  width: 90%;
  max-width:1200px;
}
</style>


<script>
function refresh(fp_id) {
  $('#basicModal').find('.modal-content').load('/detailed_fp/'+fp_id);
}

function refresh_client(client_ip) {
  $('#basicModal').find('.modal-content').load('/client_info/'+client_ip);
}
</script>

<ol class="breadcrumb">
  <li class="breadcrumb-item">
    <a href="/index">Dashboard</a>
  </li>
  <li class="breadcrumb-item active">Fingerprinting Results</li>
</ol>


<div class="card mb-3">
  <div class="card-header">
    <i class="fa fa-table"></i>TLS Connections</div>
  <div class="card-body">
    <div class="table-responsive">
      <table class="table table-bordered" id="dataTable" width="100%" cellspacing="0">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Client IP</th>
            <th>Client Port</th>
            <th>Server IP</th>
            <th>Server Port</th>
            <th>Protocol</th>
            <th>Probable Application</th>
            <th>Probable OS</th>
            <th>Min Implementation Date</th>
            <th>Max Implementation Date</th>
          </tr>
        </thead>
        <tbody>
  	% for i in range(len(fps)):
          <tr>
            <td>{{str(fps[i]['timestamp'])[:-4]}}</td>
	    <td><a onclick="refresh_client('{{fps[i]['source_addr']}}')" id="cl_{{i}}" data-toggle="modal" data-target="#basicModal" href="/client_info/{{fps[i]['source_addr']}}">{{fps[i]['source_addr']}}</a></td>
            <td>{{fps[i]['source_port']}}</td>
            <td>{{fps[i]['dest_addr']}}</td>
            <td>{{fps[i]['dest_port']}}</td>
            <td>{{fps[i]['protocol']}}</td>
            <td><a onclick="refresh('{{i}}')" id="fp_{{i}}" data-toggle="modal" data-target="#basicModal" href="/detailed_fp/{{i}}">{{fps[i]['fingerprint']['process_info'][0]['process']}}</a></td>
            % if 'os_info' in fps[i]['fingerprint']:
              <td>{{fps[i]['fingerprint']['os_info'][0]['os'] + ' (' + fps[i]['fingerprint']['os_info'][0]['os_version'] + ')'}}</td>
	    % else:
	      <td>Unknown</td>
	    % end
            <td>{{fps[i]['fingerprint']['min_implementation_date']}}</td>
            <td>{{fps[i]['fingerprint']['max_implementation_date']}}</td>
          </tr>
	% end
        </tbody>
      </table>
    </div>
  </div>
  <div class="card-footer small text-muted">Updated yesterday at 11:59 PM</div>
</div>


<div class="modal fade" id="basicModal" tabindex="-1" role="dialog" aria-labelledby="basicModal" aria-hidden="true">
    <div class="modal-dialog modal-xl" style="width:auto;">
        <div id='fingerprintModal' class="modal-content">
        </div>
    </div>
  </div>
</div>