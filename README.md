# iam_generator
Generates AWS IAM Users, Groups, Roles, and Managed Policies from a YAML configuration and Jinja2 Templates

## Build Environment

A Python 2.7 interpreter with the following libraries installed:

```
sudo pip install jinja2
sudo pip install troposphere
```

**NOTE:** At present, build is tested on OSX and Linux.  Pull requests welcome for Windows build support!

## General Function

Everything is driven by the config.yaml file.  In this file you describe your account structure, and desired managed policies, roles, users and groups.

Managed policy json structure is kept in [jinja2 templates](http://jinja.pocoo.org/docs/2.9/) files to allow for variable substitution for specific customization of ARNs and trusts etc.

When build.py is executed a CloudFormation template is built per account.  They are available in the output_templates directory to be uploaded to [CloudFormation](https://aws.amazon.com/cloudformation/) for deployment in each account.

This project wouldn't be possible without the hard work done by the [Troposphere](https://github.com/cloudtools/troposphere) and [Jinja](https://github.com/pallets/jinja) project teams.  Thanks!

## config.yaml key sections

There are five main sections of the config.yaml:

```yaml
global:
  ...
accounts:
  ...
policies:
  ...
roles:
  ...
users:
  ...
groups:
  ...
```

### `global:` section

Controls our generated templates behaviour.  There are two key sections.  `names:` and `template_outputs`.

The `names:` section looks like this:

```yaml
global:
  names:
    policies: False
    roles: True
    users: True
    groups: True
```

This section allows control over the IAM Naming of the resources.  When values are set to `True` they will be explicitly named based on the config.yaml entry.  When set to `False` CloudFormation will generate a name for you.

For example:

```yaml
policies:
  cloudFormationAdmin:
    description: CloudFormation Administrator
    policy_file: cloudFormationAdmin.j2
```

if `policies: True` is set, the name of the managed policy that CloudFormation creates will be `cloudFormationAdmin`.  If `polices: False` then CloudFormation will generate a unique value using the stack prefix and a suffix eg: `PolicyStack-cloudFormationAdmin-ACH753NADF`.

If the `global:` section is omitted, it will function with the following default values:

```yaml
global:
  names:
    policies: False
    roles: True
    users: True
    groups: True
  template_outputs: enabled
```

The `template_outputs:` value allows control over whether the CloudFormation templates will include Output values for the elements they create.  There is a limit in Cloudformation templates of 60 output values.  You will hit this much sooner than the 200 Resource limit.  The main reason to include an output is so it can be imported in a stack layered above.  If you don't intend on layering any stacks above this one then disabling outputs is absolutely fine.

Set `template_outputs: enabled` to include template outputs.  Set `template_outputs: disabled` to disable output values for templates.

### `accounts:` section

Here's an example of the accounts section:

```yaml
accounts:
  central:
    id: 123456678910
    parent: true
    saml_provider: ProdADFS
  dev1:
    id: 109876543210
  dev2:
    id: 309876543210
  prod:
    id: 209876543210
```

`accounts:` is a dictionary of friendly account names.  These friendly names can be used throughout the rest of the YAML file and are available to the jinja2 templates.

Note that `saml_provider` is optional.  If it is used in a Role's `trust:` list it will generate the appropriate trust policy for console federation.

Account resolution in the yaml:

* Use the keyword `all` to refer to all of the accounts in the `accounts:` section.
* Use the keyword `parent` to refer to the account you've marked as `parent: true`.
* Use the keyword `children` to refer to all accounts except the parent.
* You can also refer to a specific account by friendly name or it's ID.  eg: `dev1`
* You can also use python regular expressions.  eg: `dev.*` to target both developement accounts.

Using these mechanisms it should be easy to specifically manage what account each element lands in.

### `policies:` section

#### Managed Policies derived from a jinja2 template

Here's an example of a managed policy based on a jinja2 policy template:

```yaml
policies:
  cloudFormationAdmin:
    description: CloudFormation Administrator
    policy_file: cloudFormationAdmin.j2
    template_vars:
      cloudformation_bucket: bucket-cloudformation
    in_accounts:
      - parent
      - dev.*
```

This will create a managed policy with the name cloudFormationAdmin (along with the prefix and suffix that CloudFormation Adds automatically).  It will base the policy document on the contents of of the cloudFormationAdmin.j2 jinja2 template.  It will be placed into the accounts 123456678910 (which is our `parent`) as well as accounts 109876543210 and 309876543210 because their friendly names (`dev1` and `dev2`) match our regular expression `dev.*`.

Lets dissect this a bit.

`policies:` is a dictionary of policy names.  This assures they are kept unique within the account and generated CloudFormation template.

`policy_file:` needs to be located in the `/policy/` directory, and would look something like this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::{{ template_vars.cloudformation_bucket }}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": ["arn:aws:s3:::{{ template_vars.cloudformation_bucket }}/*"]
    }
  ]
}
```

Notice the variable substitution in the template ``{{ template_vars.cloudformation_bucket }}``.

Notice the value for this is derived from this section of the config.yaml:

```yaml
...
    template_vars:
      cloudformation_bucket: bucket-cloudformation
...
```

Jinja2 templates will get the following variable namespaces passed to them:

* `template_vars` as described above.
* `account` which is the account ID of the account that is being worked on.
* `parent_account` which is the account ID of the account marked as `parent: true`.
* `config` which is the entire config.yaml file!

#### Managed Policies for sts:AssumeRole (auto generated!)

Here's an example of the yaml to create a managed policy for sts:AssumeRole with the specified roles into the specified accounts.

```yaml
policies:
  assumeAdmin:
    description: Allow assumption of the Admin role in all children accounts from the parent
    assume:
      roles:
        - Admin
      accounts:
        - children
    in_accounts:
      - parent
```

This will create this policy document . . .

```json
"Version": "2012-10-17",
"Statement": [
  {   
    "Action": "sts:AssumeRole",
    "Effect": "Allow",
    "Resource": "arn:aws:iam::109876543210:role/Admin"
  },
  {   
    "Action": "sts:AssumeRole",
    "Effect": "Allow",
    "Resource": "arn:aws:iam::309876543210:role/Admin"
  },
  {   
    "Action": "sts:AssumeRole",
    "Effect": "Allow",
    "Resource": "arn:aws:iam::209876543210:role/Admin"
  },
]
```

. . . and insert it into the CloudFormation template for account 123456678910 (which was marked parent).

### `roles:` section

#### Example of a role that can be assumed from another account.

```yaml
roles:
  NetworkAdmin:
    trusts:
      - parent
    managed_policies:
      - arn:aws:iam::aws:policy/job-function/NetworkAdministrator
      - arn:aws:iam::aws:policy/ReadOnlyAccess
      - cloudFormationAdmin
    in_accounts:
      - all
```

This will create a role called NetworkAdmin.  It will have two AWS managed policies, and one policy referenced from the `policies:` section of the config.yaml.

The assume role policy document will be automatically generated to trust the parent:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456678910:root"
      }
    }
  ]
}
```

#### Example of an ec2 role

```yaml
roles:
  s3andDynamoWrite:
    trusts:
      - ec2.amazonaws.com
    inline_policies: []
    managed_policies:
      - arn:aws:iam::aws:policy/AmazonS3FullAccess
      - arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess
      - arn:aws:iam::aws:policy/AmazonElasticMapReduceFullAccess
    in_accounts:
      - all
```
In this case our `trusts:` is ec2.amazonaws.com.  This can be any service like config.amazonaws.com, lambda.amazonaws.com, etc.

Since we're trusting ec2.amazonaws.com we will automatically create an instance profile for this role so it can be used from ec2.  No additional configuration required.

#### Example of a federated role.
In cases that we have a `saml_provider:` in our parent account we can reference it in our trust.


```yaml
roles:
  AWS_Admins:
    trusts:
      - ProdADFS
    managed_policies:
      - assumeAdmin
    in_accounts:
      - parent
```

This will generate the following assume role policy document automatically . . .

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      },
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456678910:saml-provider/ProdADFS"
      }
    }
  ]
}
```

. . . and place it (along with the role definition) in the parent CloudFormation template.

### `users:` section

#### An example of a user that is not a member of a group, and has a managed_policy directly attached.

```yaml
users:
  adam:
    managed_policies:
      - assumeAdmin
    password: CHANGEME
    in_accounts:
      - parent
```
Optionally specify a `password:` for the user.  The flag is set to force a password change at first login.  The password is clear text, so be careful!

#### An example of a user as a member of groups

```yaml
users:
  adam:
    groups:
      - Admins
    in_accounts:
      - parent
```

Our `group:` field is the name of a group.  This can be a name that already exists, or is in the config.yaml file.  Existing groups just need to be the name of the group, not an ARN.

### `groups:` section

```yaml
groups:
  Admins:
    managed_policies:
      - assumeAdmin
      - arn:aws:iam::aws:policy/ReadOnlyAccess
    in_accounts:
      - parent
```

`groups:` is once again a dictionary of group names that you'd like created.  It allows for a list of `managed_policies:` to attach.  These can be either an existing managed policy arn, or the name of a policy created in the `policies:` section of the YAML.

### `retain_on_delete` variable

CloudFormation permits retention on deletion of a resource.  This is described [here](http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html).

For any resource in the `policies:` `roles:` `groups:` or `users:` section include `retain_on_delete: true` to configure the CloudFormation template to retain that resource on deletion.  This let's you keep a resource that may not necessarily remain under management of this CloudFormation template any longer.

eg:

```yaml
roles:
  NetworkAdmin:
    retain_on_delete: true
    trusts:
      - parent
    managed_policies:
      - arn:aws:iam::aws:policy/job-function/NetworkAdministrator
      - arn:aws:iam::aws:policy/ReadOnlyAccess
      - cloudFormationAdmin
    in_accounts:
      - all
```

If this section is removed from the config.yaml, and a stack-update executed, the 'NetworkAdmin' Role will persist in the account and no longer be managed by CloudFormation.

Default value is `retain_on_delete: false` which does not need to be explicitly declared anywhere.  This matches the default behaviour of CloudFormation.

### Importing resources from other templates

You are able to specify the keyword of `import:` within the config.yaml file.  Use this for managed_policies, users, groups, or roles. This will substiute the appropriate [Fn:ImportValue](http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-importvalue.html) within the template to import from an existing CloudFormation templates Exports.

Example of an import for a role:

```yaml
roles:
  NetworkAdmin:
    trusts:
      - parent
    managed_policies:
      - import:name_of_cfn_export
    in_accounts:
      - all
```
## Visualization

There's a visualization generator script under directory viz/ that generates
.dot files (http://www.graphviz.org/content/dot-language) for nice visualizations
of your accounts' configuration and resources.

Get started by downloading the required python packages:

```
 cd viz/
 pip install -r requirements.txt
```

The generator (viz.py) takes 3 input parameters:

* config_file: any of your aws-iam-generator configuration file (see ../sample_configs/config-complex.yaml for an example)
* viz_file: choose from multiple jinja2 templates for different types of visualizations (eg, viz/viz-dot-template-trusts) or create your own!
* output_file: give a name to the output .dot file to be generated

For help, type:

```bash
python viz.py --help
```

You can run the visualizations like this:

```
cd viz/
python viz.py ../sample_configs/config-complex.yaml templates/viz-dot-template-trusts.j2 output/viz-dot-template-trusts.dot
```

This will generate the output.dot file with a visualization of the "account trusted resources".

If you have graphviz/dot installed here's a single-liner:

```
 python viz.py ../sample_configs/config-complex.yaml \
   templates/viz-dot-template-trusts.j2 \
   output/viz-dot-template-trusts.dot \
 && dot -Tpng output/viz-dot-template-trusts.dot \
   -o output/viz-dot-template-trusts.png \
 && open output/viz-dot-template-trusts.png
```

You can use different layout algorithms in Dot using the -K option for better visualizations. Please check http://www.graphviz.org/ for further details.

Check out some visualizations (PNG files) under viz/output generated through the following commands:

### Accounts and Trusts

Template File: templates/viz-dot-template-trusts.j2

```bash
 export config_file="../sample_configs/config-complex.yaml"
 export viz_file_prefix="viz-dot-template-trusts"

 python viz.py "$config_file" \
   "templates/$viz_file_prefix.j2" "output/$viz_file_prefix.dot" \
   && dot -Tpng "output/$viz_file_prefix.dot" -o "output/$viz_file_prefix.png" \
   && open "output/$viz_file_prefix.png"
```

### Accounts, Trusts and Roles

Template File: templates/viz-dot-template-trusts-with-roles.j2

```bash
 export config_file="../sample_configs/config-complex.yaml"
 export viz_file_prefix="viz-dot-template-trusts-with-roles"

 python viz.py "$config_file" \
   "templates/$viz_file_prefix.j2" "output/$viz_file_prefix.dot" \
   && dot -Tpng "output/$viz_file_prefix.dot" -o "output/$viz_file_prefix.png" \
   && open "output/$viz_file_prefix.png"
```

### Accounts Details (records)

Template File: templates/viz-dot-template-accounts-details-records.j2

```bash
 export config_file="../sample_configs/config-complex.yaml"
 export viz_file_prefix="viz-dot-template-accounts-details-records"

 python viz.py "$config_file" \
   "templates/$viz_file_prefix.j2" "output/$viz_file_prefix.dot" \
   && dot -Tpng "output/$viz_file_prefix.dot" -o "output/$viz_file_prefix.png" \
   && open "output/$viz_file_prefix.png"
```

### Account Details (graph)

Template File: templates/viz-dot-template-accounts-details-graph.j2

```bash
 export config_file="../sample_configs/config-complex.yaml"
 export viz_file_prefix="viz-dot-template-accounts-details-graph"

 python viz.py "$config_file" \
   "templates/$viz_file_prefix.j2" "output/$viz_file_prefix.dot" \
   && dot -K circo -Tpng "output/$viz_file_prefix.dot" -o "output/$viz_file_prefix.png" \
   && open "output/$viz_file_prefix.png"
```

__Note__ the -K option here to use the 'circo' layout algorithm.

### Creating new visualizations

New visualizations can be easily created by creating  new jinja2 templates under viz/templates/ that will be used to generate new
.dot files. The 'config' object created in viz.py is exposed to the templates which consists of a collection of all other relevant objects including accounts, groups, roles, users, policies, and trusts.
