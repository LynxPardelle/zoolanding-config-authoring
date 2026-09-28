"""Closed Config production authority: fresh source, policy hashes and 24h TTL."""
import datetime
import hashlib
import json
import re
import subprocess
ROLES={"LynxPardelle/zoolanding-config-authoring":("zoolanding-config-authoring-production-deploy",),
       "LynxPardelle/zoolanding-config-runtime-read":("zoolanding-config-runtime-read-production-github-deploy","zoolanding-config-runtime-read-production-cfn-exec")}
def reject():raise ValueError("native_release_authority_rejected")
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
def command(args):
 result=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if result.returncode:reject()
 return result.stdout.strip()
def source_authority(env,test_sha=None,run=command):
 repo=env.get("GITHUB_REPOSITORY");sha=env.get("GITHUB_SHA","")
 if repo not in ROLES or env.get("GITHUB_REF")!="refs/heads/main" or env.get("GITHUB_EVENT_NAME")!="workflow_dispatch" or not re.fullmatch('[a-f0-9]{40}',sha):reject()
 commit=json.loads(run(['gh','api',f'repos/{repo}/git/commits/{sha}']))
 parents=commit.get('parents',[])
 if commit.get('sha')!=sha or len(parents)!=2:reject()
 parent=parents[1].get('sha')
 if not re.fullmatch('[a-f0-9]{40}',str(parent)) or test_sha is not None and parent!=test_sha:reject()
 for branch,expected in [('main',sha),('test',parent)]:
  actual=json.loads(run(['gh','api',f'repos/{repo}/git/ref/heads/{branch}']))
  if actual.get('object',{}).get('sha')!=expected:reject()
 return {'repository':repo,'mainSha':sha,'testSha':parent}
def permission_authority(repository,aws):
 if repository not in ROLES:reject()
 caller=aws('sts','get-caller-identity');expected=ROLES[repository][0]
 if caller.get('Account')!='765932874577' or not str(caller.get('Arn','')).startswith(f'arn:aws:sts::765932874577:assumed-role/{expected}/'):reject()
 result={}
 for name in ROLES[repository]:
  role=aws('iam','get-role','--role-name',name)['Role'];arn='arn:aws:iam::765932874577:role/'+name
  if role.get('Arn')!=arn or not role.get('RoleId') or role.get('PermissionsBoundary'):reject()
  inline=aws('iam','list-role-policies','--role-name',name);attached=aws('iam','list-attached-role-policies','--role-name',name)
  if inline.get('IsTruncated') or attached.get('IsTruncated') or attached.get('AttachedPolicies')!=[] or not isinstance(inline.get('PolicyNames'),list):reject()
  policies={p:digest(aws('iam','get-role-policy','--role-name',name,'--policy-name',p)['PolicyDocument']) for p in sorted(inline['PolicyNames'])}
  result[name]={'arn':arn,'roleId':role['RoleId'],'trustSha256':digest(role['AssumeRolePolicyDocument']),'policyHashes':policies,'boundary':None}
 return result
def review_window(description,now=None):
 raw=description.get('CreationTime')
 if not isinstance(raw,str):reject()
 try:created=datetime.datetime.fromisoformat(raw.replace('Z','+00:00'))
 except (ValueError,TypeError):reject()
 if created.tzinfo is None:reject()
 created=created.astimezone(datetime.timezone.utc);now=now or datetime.datetime.now(datetime.timezone.utc);expires=created+datetime.timedelta(hours=24)
 if now.tzinfo is None or now<created-datetime.timedelta(minutes=1) or now>=expires:reject()
 return {'createdAt':created.isoformat(),'expiresAt':expires.isoformat()}

def parse_selection(raw):
 if not isinstance(raw,str) or len(raw.encode('utf-8'))>4096:reject()
 def pairs(values):
  result={}
  for key,value in values:
   if key in result:reject()
   result[key]=value
  return result
 result=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:reject())
 if not isinstance(result,dict):reject()
 return result
