# --
# File: aws_investigate_view.py
# --


def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if (data):
        if "instance" in ctx_result['param'].keys():
            ctx_result['data'] = data[0]['Reservations'][0]['Instances'][0]
            ctx_result['volumes'] = data[1]['volumes']
            ctx_result['secgrps'] = data[2]['securitygroups']
            ctx_result['tags'] = data[3]['tags']
        elif "user" in ctx_result['param'].keys():
            ctx_result['data'] = data[0]

    if (summary):
        ctx_result['summary'] = summary

    return ctx_result


def display_instance(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'display_instance.html'


def display_user(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'display_user.html'
