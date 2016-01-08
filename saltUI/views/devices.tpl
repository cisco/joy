<!--
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
-->

% rebase('base.tpl', title='Page Title')

<style>
.box {   
    float: left;
    width: 15px;
    height: 15px;
    margin: 3px 3px 3px 3px;
    border-width: 1px;
    border-style: solid;
    border-color: rgba(0,0,0,.2);
}
</style>

<script>
$('body').on('hidden.bs.modal', '.modal', function () {
  $(this).removeData('bs.modal');
});
</script>


<h2>Devices Found on Subnet: {{subnet}}</h2>

<div class="col-md-14">

    % for k in devices.keys():
      <div class="jumbotron specialjum">
      <h2>IP Address: {{k}}</h2>
      <div class="row">
	<div style="float: left;">
	  <h3>Overview:</h3>
        <table>
	  <tr>
	    <td>Total Flows:</td><td>{{devices[k][0]}}</td>
	  </tr>
	</table>
	</div>	

	<div style="float: left; padding-left: 50px;">
	  <h3>Encryption:</h3>
        <table>
	  <tr>
	    <td>Recommended (scs):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td>{{devices[k][1]}}</td>
	  </tr>
	  <tr>
	    <td>Legacy (scs):</td><td>{{int(devices[k][2])}}</td>
	  </tr>
	  <tr>
	    <td>Avoid (scs):</td><td>{{int(devices[k][3])}}</td>
	  </tr>
	</table>
	</div>

	<div style="float: left; padding-left: 50px;">
	  <h3>&nbsp;</h3>
        <table>
	  <tr>
	    <td>TLS 1.2:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td>{{devices[k][9]}}</td>
	  </tr>
	  <tr>
	    <td>TLS 1.1:</td><td>{{int(devices[k][8])}}</td>
	  </tr>
	  <tr>
	    <td>TLS 1.0:</td><td>{{int(devices[k][7])}}</td>
	  </tr>
	  <tr>
	    <td>SSL 3.0:</td><td>{{int(devices[k][6])}}</td>
	  </tr>
	  <tr>
	    <td>SSL 2.0:</td><td>{{int(devices[k][5])}}</td>
	  </tr>
	  <tr>
	    <td>Unknown:</td><td>{{int(devices[k][4])}}</td>
	  </tr>
	</table>
	</div>

      </div>

        <div class="span4 collapse-group" style="padding-top: 25px;">
          <p><a class="btn" data-toggle="collapse" data-target="#viewdetails{{k.replace('.','')}}">View Flow Details &raquo;</a></p>
           <div class="collapse" id="viewdetails{{k.replace('.','')}}">
  <table data-toggle="table" id="table" class="table table-striped" data-sort-name="p_mal" data-sort-order="desc">
    <thead>
      <tr>
        % for name in classifier_names:
	  <th data-field="p_{{name}}" data-sortable="true">P({{name}})</th>
        % end
	% for (abbrev, name) in to_display_names:
          <th data-field="{{abbrev}}" data-sortable="true">{{name}}</th>
	% end
      </tr>
    </thead>
    <tbody>
    % for i in range(len(results[k])):
      % item = results[k][i]
      <tr>
        % for j in range(len(classifier_names)):
        <td><div id="{{item[0][j]}}" class="box" style="background-color:#{{item[9][j]}};"></div><a id="{{item[0][j]}}" data-toggle="modal" data-target="#basicModal" href="/advancedInfo/{{item[1].replace('.','')+item[2].replace('.','')+str(item[3])+str(item[4])+str(item[7]+item[8])}}">{{item[0][j]}}</a></td>
	% end
	% for x in item[13]:
          <td>{{x}}</td>
	% end
      </tr>
    % end
    </tbody>
  </table>
	   </div>
        </div>

      </div>
    % end

</div>

<div class="modal fade" id="basicModal" tabindex="-1" role="dialog" aria-labelledby="basicModal" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
        </div>
    </div>
  </div>
</div>