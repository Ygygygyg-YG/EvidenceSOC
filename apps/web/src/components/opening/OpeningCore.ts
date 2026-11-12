export const ANIMATION_SPEED = 1.8;

export type OpeningCoreState = {
  supported: boolean; running: boolean; disposed: boolean; frames: number; requested: boolean;
  reducedMotion: boolean; hidden: boolean; smallScreen: boolean; width: number; height: number;
  pixelWidth: number; pixelHeight: number; dpr: number; fpsLimit: number; activeRaf: boolean;
  contextLost: boolean; fallbackReason: string | null; resourcesReleased: boolean;
  listenersAttached: boolean; elapsedSeconds: number; animationSpeed: number;
  animationTimeSeconds: number; webglVersion: string | null;
};
export type OpeningCoreController = {
  start(): OpeningCoreController; stop(): OpeningCoreController; renderOnce(): boolean;
  dispose(): void; getState(): OpeningCoreState;
};
export type OpeningCoreOptions = {
  reducedMotion?: boolean;
  onFallback?: (detail: { reason: string; message: string; state: OpeningCoreState }) => void;
};
type Orbit = { radius: number; tilt: number; roll: number };
type Mesh = { vao: WebGLVertexArrayObject; count: number };

const SPHERE_VERTEX = `#version 300 es
precision highp float;layout(location=0) in vec3 aPosition;layout(location=1) in vec3 aNormal;
uniform mat4 uModel;uniform mat4 uViewProjection;out vec3 vWorld;out vec3 vNormal;out vec3 vLocal;
void main(){vec4 world=uModel*vec4(aPosition,1.0);vWorld=world.xyz;vNormal=mat3(uModel)*aNormal;vLocal=aPosition;gl_Position=uViewProjection*world;}`;
const SPHERE_FRAGMENT = `#version 300 es
precision highp float;
in vec3 vWorld;in vec3 vNormal;in vec3 vLocal;
uniform vec3 uEye;uniform vec3 uTint;uniform float uTime;uniform float uGain;
out vec4 outColor;
void main(){
  vec3 N=normalize(vNormal);vec3 V=normalize(uEye-vWorld);vec3 R=reflect(-V,N);
  vec3 L=normalize(vec3(-0.46,0.69,0.71));vec3 H=normalize(L+V);vec3 Q=normalize(vLocal);
  float diffuse=max(dot(N,L),0.0);
  float fresnel=pow(1.0-max(dot(N,V),0.0),3.4);
  float keySpec=pow(max(dot(N,H),0.0),68.0);
  float reflectedSpec=pow(max(dot(R,normalize(vec3(-0.48,0.73,0.95))),0.0),28.0);
  float drift=sin(uTime*0.055+Q.y*1.6)*0.006;
  float ribbon=exp(-pow((0.66*N.x-0.20*N.y+0.62*N.z-0.34+drift)/0.108,2.0));
  float broad=exp(-pow((-0.42*N.x+0.40*N.y+0.82*N.z-0.62)/0.34,2.0));
  float innerShade=exp(-pow((0.46*N.x+0.30*N.y+0.72*N.z-0.61)/0.17,2.0));
  float upperFill=smoothstep(-0.82,0.72,N.y)*0.008;
  float grain=sin(Q.x*63.0+sin(Q.y*39.0))*sin(Q.z*51.0)*0.0012;
  vec3 color=vec3(0.009,0.014,0.017);
  color+=diffuse*vec3(0.023,0.031,0.035);
  color+=broad*vec3(0.050,0.064,0.070);
  color+=ribbon*vec3(0.40,0.49,0.51);
  color*=1.0-innerShade*0.23;
  color+=keySpec*vec3(0.38,0.42,0.42)+reflectedSpec*vec3(0.11,0.14,0.15);
  color+=fresnel*uTint*0.13+vec3(upperFill)+grain;
  color=pow(max(color*uGain,vec3(0.0)),vec3(0.72));
  outColor=vec4(clamp(color,0.0,1.0),1.0);
}`;
const LINE_VERTEX = `#version 300 es
precision highp float;layout(location=0) in vec3 aPosition;uniform mat4 uModel;uniform mat4 uViewProjection;out float vDepth;
void main(){vec4 world=uModel*vec4(aPosition,1.0);vDepth=world.z;gl_Position=uViewProjection*world;}`;
const LINE_FRAGMENT = `#version 300 es
precision highp float;in float vDepth;uniform vec3 uColor;out vec4 outColor;
void main(){float alpha=mix(0.27,0.69,smoothstep(-1.5,1.5,vDepth));outColor=vec4(uColor*alpha,alpha);}`;

function identity() { return new Float32Array([1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1]); }
function multiply(a: Float32Array, b: Float32Array) {
  const r = new Float32Array(16);
  for (let col=0;col<4;col+=1) for (let row=0;row<4;row+=1) r[col*4+row]=a[row]*b[col*4]+a[4+row]*b[col*4+1]+a[8+row]*b[col*4+2]+a[12+row]*b[col*4+3];
  return r;
}
function model(rx: number, ry: number, scale: number, position: number[]) {
  const cx=Math.cos(rx),sx=Math.sin(rx),cy=Math.cos(ry),sy=Math.sin(ry);
  return new Float32Array([cy*scale,0,-sy*scale,0,sy*sx*scale,cx*scale,cy*sx*scale,0,sy*cx*scale,-sx*scale,cy*cx*scale,0,position[0],position[1],position[2],1]);
}
function perspective(aspect: number) {
  const f=(1/Math.tan(43*Math.PI/360))*Math.min(1,aspect),near=.1,far=30,out=new Float32Array(16);
  out[0]=f/aspect;out[5]=f;out[10]=(far+near)/(near-far);out[11]=-1;out[14]=2*far*near/(near-far);
  const view=identity();view[14]=-5.2;return multiply(out,view);
}
function orbitPoint(orbit: Orbit, angle: number) {
  const x=orbit.radius*Math.cos(angle),y=orbit.radius*Math.sin(angle)*Math.cos(orbit.tilt),z=orbit.radius*Math.sin(angle)*Math.sin(orbit.tilt);
  return [x*Math.cos(orbit.roll)-y*Math.sin(orbit.roll),x*Math.sin(orbit.roll)+y*Math.cos(orbit.roll),z];
}
function rotateY(point: number[], angle: number) { return [Math.cos(angle)*point[0]+Math.sin(angle)*point[2],point[1],-Math.sin(angle)*point[0]+Math.cos(angle)*point[2]]; }

/** Typed production adaptation of the accepted P1 WebGL2 evidence sculpture. */
export function createOpeningCore(canvas: HTMLCanvasElement, options: OpeningCoreOptions = {}): OpeningCoreController {
  const host=canvas.ownerDocument.defaultView ?? window, documentRef=canvas.ownerDocument;
  const notify=options.onFallback ?? (()=>undefined), forceReduced=options.reducedMotion===true;
  const motionMedia=host.matchMedia('(prefers-reduced-motion: reduce)'),smallMedia=host.matchMedia('(max-width: 767px)');
  let gl: WebGL2RenderingContext | null=null,sphereProgram: WebGLProgram | null=null,lineProgram: WebGLProgram | null=null,sphereMesh: Mesh | null=null;
  let sphereUniforms: Record<string,WebGLUniformLocation|null> | null=null,lineUniforms: Record<string,WebGLUniformLocation|null> | null=null;
  const resources={programs:[] as WebGLProgram[],buffers:[] as WebGLBuffer[],vaos:[] as WebGLVertexArrayObject[]};
  const mediaCleanups:Array<()=>void>=[],orbits:Orbit[]=[{radius:1.64,tilt:1.19,roll:-.39},{radius:1.42,tilt:1.25,roll:.99}],orbitMeshes:Mesh[]=[];
  let resizeObserver:ResizeObserver|null=null,raf=0,requested=false,running=false,disposed=false,supported=false,contextLost=false,resourcesReleased=false,listenersAttached=false,fallbackNotified=false;
  let reason:string|null=null,cssWidth=0,cssHeight=0,dpr=1,frames=0,elapsed=0,previousTick:number|null=null,previousPaint:number|null=null,version:string|null=null;
  let reduced=forceReduced||motionMedia.matches,small=smallMedia.matches;
  const hidden=()=>documentRef.hidden;
  const state=():OpeningCoreState=>({supported,running,disposed,frames,requested,reducedMotion:reduced,hidden:hidden(),smallScreen:small,width:cssWidth,height:cssHeight,pixelWidth:canvas.width,pixelHeight:canvas.height,dpr,fpsLimit:30,activeRaf:raf!==0,contextLost,fallbackReason:reason,resourcesReleased,listenersAttached,elapsedSeconds:elapsed,animationSpeed:ANIMATION_SPEED,animationTimeSeconds:elapsed*ANIMATION_SPEED,webglVersion:version});
  function cancelFrame(){if(raf){host.cancelAnimationFrame(raf);raf=0;}running=false;previousTick=null;previousPaint=null;}
  function releaseResources(){if(resourcesReleased)return;if(gl){for(let i=resources.vaos.length-1;i>=0;i-=1)gl.deleteVertexArray(resources.vaos[i]);for(let i=resources.buffers.length-1;i>=0;i-=1)gl.deleteBuffer(resources.buffers[i]);for(let i=resources.programs.length-1;i>=0;i-=1)gl.deleteProgram(resources.programs[i]);}resources.vaos.length=resources.buffers.length=resources.programs.length=orbitMeshes.length=0;sphereMesh=null;sphereProgram=null;lineProgram=null;sphereUniforms=null;lineUniforms=null;resourcesReleased=true;}
  function fallback(why:string,error?:unknown){if(disposed)return;reason=why;supported=false;requested=false;cancelFrame();releaseResources();if(fallbackNotified)return;fallbackNotified=true;queueMicrotask(()=>{if(disposed)return;try{notify({reason:why,message:error instanceof Error?error.message:String(error??''),state:state()});}catch{/* host callbacks cannot break lifecycle */}});}
  function shader(type:number,source:string){if(!gl)throw new Error('WebGL2 unavailable.');const item=gl.createShader(type);if(!item)throw new Error('Unable to allocate WebGL shader.');gl.shaderSource(item,source);gl.compileShader(item);if(!gl.getShaderParameter(item,gl.COMPILE_STATUS)){const log=gl.getShaderInfoLog(item)||'Unknown shader compile error.';gl.deleteShader(item);throw new Error(log);}return item;}
  function program(vertex:string,fragment:string){if(!gl)throw new Error('WebGL2 unavailable.');let vs:WebGLShader|null=null,fs:WebGLShader|null=null;try{vs=shader(gl.VERTEX_SHADER,vertex);fs=shader(gl.FRAGMENT_SHADER,fragment);const item=gl.createProgram();if(!item)throw new Error('Unable to allocate WebGL program.');resources.programs.push(item);gl.attachShader(item,vs);gl.attachShader(item,fs);gl.linkProgram(item);if(!gl.getProgramParameter(item,gl.LINK_STATUS))throw new Error(gl.getProgramInfoLog(item)||'Unable to link WebGL program.');return item;}finally{if(vs)gl.deleteShader(vs);if(fs)gl.deleteShader(fs);}}
  function allocateBuffer(target:number,data:BufferSource){if(!gl)throw new Error('WebGL2 unavailable.');const item=gl.createBuffer();if(!item)throw new Error('Unable to allocate WebGL buffer.');resources.buffers.push(item);gl.bindBuffer(target,item);gl.bufferData(target,data,gl.STATIC_DRAW);return item;}
  function allocateVao(){if(!gl)throw new Error('WebGL2 unavailable.');const item=gl.createVertexArray();if(!item)throw new Error('Unable to allocate WebGL vertex array.');resources.vaos.push(item);gl.bindVertexArray(item);return item;}
  function makeSphere(){if(!gl)throw new Error('WebGL2 unavailable.');const lon=64,lat=40,values:number[]=[],indices:number[]=[];for(let y=0;y<=lat;y+=1){const phi=y/lat*Math.PI;for(let x=0;x<=lon;x+=1){const theta=x/lon*Math.PI*2,p=[Math.sin(phi)*Math.cos(theta),Math.cos(phi),Math.sin(phi)*Math.sin(theta)];values.push(...p,...p);}}for(let y=0;y<lat;y+=1)for(let x=0;x<lon;x+=1){const a=y*(lon+1)+x,b=a+lon+1;indices.push(a,b,a+1,b,b+1,a+1);}const vao=allocateVao();allocateBuffer(gl.ARRAY_BUFFER,new Float32Array(values));gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,3,gl.FLOAT,false,24,0);gl.enableVertexAttribArray(1);gl.vertexAttribPointer(1,3,gl.FLOAT,false,24,12);allocateBuffer(gl.ELEMENT_ARRAY_BUFFER,new Uint16Array(indices));gl.bindVertexArray(null);return{vao,count:indices.length};}
  function makeOrbit(orbit:Orbit){if(!gl)throw new Error('WebGL2 unavailable.');const values:number[]=[];for(let i=0;i<256;i+=1)values.push(...orbitPoint(orbit,i/256*Math.PI*2));const vao=allocateVao();allocateBuffer(gl.ARRAY_BUFFER,new Float32Array(values));gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,3,gl.FLOAT,false,12,0);gl.bindVertexArray(null);return{vao,count:256};}
  function resize(){if(disposed||!supported)return false;const rect=canvas.getBoundingClientRect();cssWidth=Math.max(0,rect.width);cssHeight=Math.max(0,rect.height);dpr=Math.min(small?1:1.5,Math.max(1,host.devicePixelRatio||1));const w=Math.max(1,Math.round(cssWidth*dpr)),h=Math.max(1,Math.round(cssHeight*dpr)),changed=canvas.width!==w||canvas.height!==h;if(changed){canvas.width=w;canvas.height=h;}return changed;}
  function draw(){if(disposed||!supported||hidden()||cssWidth<=0||cssHeight<=0||!gl||!sphereProgram||!lineProgram||!sphereMesh||!sphereUniforms||!lineUniforms)return false;try{if(gl.isContextLost()){contextLost=true;fallback('context-lost');return false;}const vp=perspective(cssWidth/cssHeight);gl.viewport(0,0,canvas.width,canvas.height);gl.clearColor(0,0,0,0);gl.clearDepth(1);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);gl.enable(gl.DEPTH_TEST);gl.depthFunc(gl.LEQUAL);gl.enable(gl.BLEND);gl.blendFunc(gl.ONE,gl.ONE_MINUS_SRC_ALPHA);gl.disable(gl.CULL_FACE);const motionTime=elapsed*ANIMATION_SPEED,drift=Math.sin(motionTime*.035)*.10;gl.useProgram(sphereProgram);gl.uniformMatrix4fv(sphereUniforms.vp,false,vp);gl.uniform3f(sphereUniforms.eye,0,0,5.2);gl.uniform3f(sphereUniforms.tint,.57,.78,.83);gl.uniform1f(sphereUniforms.time,motionTime);gl.uniform1f(sphereUniforms.gain,.94);gl.bindVertexArray(sphereMesh.vao);gl.uniformMatrix4fv(sphereUniforms.model,false,model(Math.sin(motionTime*.035)*.08,motionTime*.025,1,[0,0,0]));gl.drawElements(gl.TRIANGLES,sphereMesh.count,gl.UNSIGNED_SHORT,0);const satellites=[{orbit:0,angle:2.72+motionTime*.11,scale:.066},{orbit:0,angle:.45+motionTime*.11,scale:.049},{orbit:1,angle:1.10-motionTime*.085,scale:.057}];gl.uniform1f(sphereUniforms.gain,1.13);for(const item of satellites){const point=rotateY(orbitPoint(orbits[item.orbit],item.angle),drift);gl.uniformMatrix4fv(sphereUniforms.model,false,model(0,motionTime*.08,item.scale,point));gl.drawElements(gl.TRIANGLES,sphereMesh.count,gl.UNSIGNED_SHORT,0);}gl.useProgram(lineProgram);gl.uniformMatrix4fv(lineUniforms.vp,false,vp);gl.uniformMatrix4fv(lineUniforms.model,false,model(0,drift,1,[0,0,0]));gl.uniform3f(lineUniforms.color,.40,.55,.59);gl.depthMask(false);for(const mesh of orbitMeshes){gl.bindVertexArray(mesh.vao);gl.drawArrays(gl.LINE_LOOP,0,mesh.count);}gl.depthMask(true);gl.bindVertexArray(null);gl.useProgram(null);frames+=1;return true;}catch(error){fallback('render-failed',error);return false;}}
  const canAnimate=()=>!disposed&&supported&&requested&&!reduced&&!hidden()&&cssWidth>0&&cssHeight>0;
  function tick(time:number){raf=0;if(!canAnimate()){cancelFrame();return;}if(previousTick!==null)elapsed+=Math.min(.10,Math.max(0,(time-previousTick)/1000));previousTick=time;const interval=1000/30;if(previousPaint===null||time-previousPaint>=interval-.5){if(!draw()&&!canAnimate())return;previousPaint=time;}if(canAnimate()){running=true;raf=host.requestAnimationFrame(tick);}else cancelFrame();}
  function reconcile(){if(!canAnimate()){cancelFrame();return;}if(!raf){previousTick=null;previousPaint=null;running=true;raf=host.requestAnimationFrame(tick);}}
  function refresh(){if(disposed||!supported)return;reduced=forceReduced||motionMedia.matches;small=smallMedia.matches;const changed=resize();if(!running||changed||reduced)draw();reconcile();}
  function onVisibility(){if(disposed)return;if(hidden())cancelFrame();else refresh();}
  function onContextLost(event:Event){event.preventDefault();contextLost=true;fallback('context-lost');}
  function listenMedia(media:MediaQueryList){media.addEventListener('change',refresh);mediaCleanups.push(()=>media.removeEventListener('change',refresh));}
  function removeListeners(){if(!listenersAttached)return;host.removeEventListener('resize',refresh);documentRef.removeEventListener('visibilitychange',onVisibility);canvas.removeEventListener('webglcontextlost',onContextLost);resizeObserver?.disconnect();resizeObserver=null;for(const cleanup of mediaCleanups)cleanup();mediaCleanups.length=0;listenersAttached=false;}
  const api:OpeningCoreController={start(){if(disposed||!supported||requested)return api;requested=true;resize();if(reduced||hidden()){if(!hidden())draw();}reconcile();return api;},stop(){requested=false;cancelFrame();return api;},renderOnce(){if(disposed||!supported)return false;resize();return draw();},dispose(){if(disposed)return;requested=false;cancelFrame();disposed=true;removeListeners();releaseResources();gl=null;},getState:state};
  try{gl=canvas.getContext('webgl2',{alpha:true,antialias:true,depth:true,premultipliedAlpha:true,preserveDrawingBuffer:false,powerPreference:'low-power'});if(!gl){fallback('webgl2-unavailable');return api;}version=String(gl.getParameter(gl.VERSION));sphereProgram=program(SPHERE_VERTEX,SPHERE_FRAGMENT);lineProgram=program(LINE_VERTEX,LINE_FRAGMENT);sphereUniforms={model:gl.getUniformLocation(sphereProgram,'uModel'),vp:gl.getUniformLocation(sphereProgram,'uViewProjection'),eye:gl.getUniformLocation(sphereProgram,'uEye'),tint:gl.getUniformLocation(sphereProgram,'uTint'),time:gl.getUniformLocation(sphereProgram,'uTime'),gain:gl.getUniformLocation(sphereProgram,'uGain')};lineUniforms={model:gl.getUniformLocation(lineProgram,'uModel'),vp:gl.getUniformLocation(lineProgram,'uViewProjection'),color:gl.getUniformLocation(lineProgram,'uColor')};sphereMesh=makeSphere();for(const orbit of orbits)orbitMeshes.push(makeOrbit(orbit));supported=true;listenersAttached=true;host.addEventListener('resize',refresh,{passive:true});documentRef.addEventListener('visibilitychange',onVisibility);canvas.addEventListener('webglcontextlost',onContextLost,false);listenMedia(motionMedia);listenMedia(smallMedia);if(typeof ResizeObserver!=='undefined'){resizeObserver=new ResizeObserver(refresh);resizeObserver.observe(canvas);}resize();draw();}catch(error){fallback('initialization-failed',error);removeListeners();}
  return api;
}
