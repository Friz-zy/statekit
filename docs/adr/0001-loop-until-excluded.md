# ADR 0001: loop.until is excluded (code-eval contract)

Status: accepted (user decision, 2026-08-23)
Reference revision: references/salt.lock (8b63e700637e)

## Context

`loop.until` (salt/states/loop.py) loops an execution module until a
condition is met. The condition parameter is a string of arbitrary Python
evaluated with `eval()` per iteration, with `m_ret` (the module return)
injected into scope:

    m_ret = __salt__[name](*m_args, **m_kwargs)
    if eval(condition):
        ...

Real conditions use the full Python expression grammar: subscripting and
attribute access on `m_ret`, method calls, slicing, comprehensions, `in`,
nested calls.

## Decision

`loop.until` is excluded from porting — reason class: code-eval contract.

An honest port would require embedding a Python expression interpreter in
the Go binary. Any subset dialect would silently diverge from Salt's
observable behavior for exactly the expressions users actually write,
which init.md section 45 forbids ("silently drop edge cases"). Embedding
Python at runtime is separately forbidden by the same section.

## Consequences

- The registered StateKit surface of the loop family is limited to
  `loop.until_no_eval`, whose contract is structural: it compares each
  return through a named compare operator resolved from a closed set
  (builtin comparison operators; data.subdict_match once the data/util
  layer lands). Port of until_no_eval stays planned behind that layer.
- The loop family's terminal state will be `partial` once until_no_eval
  lands, with this ADR as the exclusion annotation for until.
- Future ADRs may revisit only if StateKit ever adopts an explicit,
  documented expression language — out of scope by default.
