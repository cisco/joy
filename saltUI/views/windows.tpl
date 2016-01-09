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


<div class="col-md-14">

    % for (score, ip, contribs) in results:
      <div class="jumbotron specialjum">
      <h2>IP Address: {{ip}}</h2>
      <h2>Score: {{score}}</h2>

        <div class="span4 collapse-group" style="padding-top: 25px;">
          <p><a class="btn" data-toggle="collapse" data-target="#viewdetails{{ip.replace('.','')+str(score).replace('.','')}}">View Flow Details &raquo;</a></p>
           <div class="collapse" id="viewdetails{{ip.replace('.','')+str(score).replace('.','')}}">
  <table data-toggle="table" id="table" class="table table-striped" data-sort-name="p_mal" data-sort-order="desc">
    <thead>
      <tr>
      	<th data-field="contrib" data-sortable="true">Contribution</th>
      	<th data-field="sip_addr" data-sortable="true">IP Address</th>
      	<th data-field="dip_addr" data-sortable="true"></th>
      	<th data-field="spr" data-sortable="true">Source Port</th>
      	<th data-field="dpr" data-sortable="true">Destination Port</th>
      </tr>
    </thead>
    <tbody>
      <tr>
    % for c in contribs:
          <td>{{c['contribution']}}</td>
          <td>{{c['sip']}}</td>
          <td>{{c['dip']}}</td>
          <td>{{c['spr']}}</td>
          <td>{{c['dpr']}}</td>
      </tr>
    % end
    </tbody>
  </table>
	   </div>
        </div>

      </div>
    % end

</div>

