%% Copyright 2026, the Pyrlang authors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

%% Expression evaluator that the interop tests drive (plan step EPMD-01;
%% the same file as pyrlang-src/test/erl/py_eval.erl).
%%
%%   erl -noshell -name N@127.0.0.1 -setcookie C -pa <beam dir> -s py_eval main
%%
%% Reads one Erlang expression sequence per stdin line ("Expr."), evaluates
%% it with the bindings of earlier lines, and prints one reply line:
%%   <<<py_eval>>> ok <result as ~0tp>
%%   <<<py_eval>>> error <{Class, Reason} as ~0tp>
%% Anything else on stdout (logger output) is not a reply. End of input
%% halts the node.

-module(py_eval).

-export([main/0]).

-define(MARK, "<<<py_eval>>>").

main() ->
    loop(erl_eval:new_bindings()).

loop(Bindings) ->
    case io:get_line(standard_io, "") of
        eof ->
            halt(0);
        {error, _} ->
            halt(1);
        Line ->
            case eval(Line, Bindings) of
                {ok, Value, Bindings1} ->
                    reply("ok", Value),
                    loop(Bindings1);
                {error, Error} ->
                    reply("error", Error),
                    loop(Bindings)
            end
    end.

eval(Line, Bindings) ->
    try
        {ok, Tokens, _} = erl_scan:string(Line),
        {ok, Exprs} = erl_parse:parse_exprs(Tokens),
        {value, Value, Bindings1} = erl_eval:exprs(Exprs, Bindings),
        {ok, Value, Bindings1}
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

reply(Status, Term) ->
    Text = lists:flatten(io_lib:format("~0tp", [Term])),
    OneLine = [case C of $\n -> $\s; _ -> C end || C <- Text],
    io:format("~s ~s ~ts~n", [?MARK, Status, OneLine]).
