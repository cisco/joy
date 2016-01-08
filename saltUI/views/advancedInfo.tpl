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

<style>
.box {   
    float: left;
    width: 20px;
    height: 20px;
    margin: 0px 0px 0px 0px;
    padding: 0px 0px 0px 0px;
    border-width: 1px;
    border-style: solid;
    border-color: rgba(0,0,0,.2);
}
</style>



<div class="modal-header">
  <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
  <h4 class="modal-title" id="myModalLabel">Advanced Flow Information</h4>
</div>
<div class="modal-body">

  <table class="table">
    <tbody>
      <tr>
        <td>Source:</td>
        <td>{{info['sa']}} ({{info['sp']}})</td>
	<td>{{info['sOrgName']}}</td>
      </tr>
      <tr>
        <td>Destination:</td>
        <td>{{info['da']}} ({{info['dp']}})</td>
	<td>{{info['dOrgName']}}</td>
      </tr>
      <tr>
        <td>Length of Connection:</td>
	<td>{{info['total_time']}}ms</td>
	<td/>
      </tr>
      <tr>
        <td/><td/><td/>
      </tr>
    </tbody>
  </table>

  <h3 style="text-align:center;text-decoration:underline;">Flow Visualization</h3>
  <svg width="720" height="240">
    <defs>
      <marker id="Triangle"
              viewBox="0 0 10 10" 
              refX="1" refY="5"
              markerWidth="6" 
              markerHeight="6"
              orient="auto">
        <path d="M 0 0 L 10 5 L 0 10 z" />
      </marker>
    </defs>

    <line x1="40" y1="120" x2="466" y2="120" stroke="black" stroke-width="2" marker-end="url(#Triangle)"/>

    <circle cx="40" cy="120" r="25" style="fill:steelblue; stroke:black; stroke-width:2"></circle>
    <circle cx="500" cy="120" r="25" style="fill:steelblue; stroke:black; stroke-width:2"></circle>

    % for i in range(len(info['lengths'])):
    % if info['dirs'][i] == 1.0:
        <line x1="{{info['times'][i]/float(info['total_time'])*390 + 70}}" y1="120" x2="{{info['times'][i]/float(info['total_time'])*390 + 70}}" y2="{{(1-info['lengths'][i])*60+60}}" stroke="black" stroke-width="2"/>
    % else:
        <line x1="{{info['times'][i]/float(info['total_time'])*390 + 70}}" y1="120" x2="{{info['times'][i]/float(info['total_time'])*390 + 70}}" y2="{{240-((1-info['lengths'][i])*60+60)}}" stroke="black" stroke-width="2"/>
<!--	  <h2>{{info['lengths'][i]}}<h2>
	  <h2>{{(1-info['lengths'][i])*60+60}}<h2>
	  <h2>{{240-(1-info['lengths'][i])*60+60}}<h2>-->
    % end
    % end
  </svg>

  <h3 style="text-align:center;text-decoration:underline;">Byte Distribution</h3>
  <div style="margin-left:22.5%;">
  % for y in info['bd']:
  <br />
  % for x in y:
    <div class="box" style="background-color:#{{x}};" />
  % end
  % end
  </div>
  <br />
  <br />

</div>
<div class="modal-footer">
<button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
</div>