_autodownload_complete() {
    local cur="${2-}" mode="" prefix="" word option script directory path name i
    local -a options=(-h --help --version --create --edit --clear --run --list --debug --log --rename --log-file)
    COMPREPLY=()

    for ((i = 1; i < COMP_CWORD; i++)); do
        word="${COMP_WORDS[i]}"
        case "$word" in
            --) return 0 ;;
            --run|--create|--edit|--log-file) mode="$word" ;;
            --*) mode="" ;;
            -h) mode="" ;;
            '=')
                case "$mode" in
                    --run|--create|--edit|--log-file) mode="${mode}=" ;;
                    *) mode="" ;;
                esac
                ;;
            *)
                [[ "$mode" == --run ]] || mode=""
                ;;
        esac
    done

    case "$cur" in
        --run=*|--create=*|--edit=*|--log-file=*)
            prefix="${cur%%=*}="
            mode="$prefix"
            cur="${cur#*=}"
            ;;
    esac
    if [[ "${COMP_WORDS[COMP_CWORD]-}" == '=' ]]; then
        case "$mode" in
            --run|--create|--edit|--log-file) mode="${mode}=" ;;
        esac
        cur=""
    fi

    if [[ "$cur" == *\\* && "${COMP_WORDS[COMP_CWORD]-}" != [\'\"]* ]]; then
        IFS= read cur <<< "$cur"
    fi

    if [[ "$mode" == --log-file || "$mode" == --log-file= ]]; then
        while IFS= read -r path; do
            COMPREPLY+=("${prefix}${path}")
        done < <(compgen -f -- "$cur")
        compopt -o filenames
        if [[ -n "$prefix" && ${#COMPREPLY[@]} -eq 1 && -d "${COMPREPLY[0]#"$prefix"}" ]]; then
            COMPREPLY[0]+=/
            compopt -o nospace
        fi
        return 0
    fi

    if [[ "$mode" != *= && ( -z "$cur" || "$cur" == -* ) ]]; then
        for option in "${options[@]}"; do
            [[ "$option" == "$cur"* ]] && COMPREPLY+=("$option")
        done
    fi
    if [[ "$cur" == -* && "$mode" != *= ]]; then
        return 0
    fi

    case "$mode" in
        --run|--run=|--create|--create=|--edit|--edit=)
            script="$1"
            if [[ "$script" == *\\* ]]; then
                IFS= read script <<< "$script"
            fi
            case "$script" in
                \~/*) script="$HOME/${script#\~/}" ;;
                */*) ;;
                *) script=$(type -P -- "$script") || return 0 ;;
            esac
            script=$(readlink -f -- "$script") || return 0
            directory="${script%/*}"
            if [[ "$mode" == --create || "$mode" == --create= ]]; then
                if [[ ! -e "$directory/plugins/plugin.json" && ! -L "$directory/plugins/plugin.json" ]]; then
                    if [[ plugin == "$cur"* ]]; then
                        COMPREPLY+=("${prefix}plugin")
                    elif [[ plugin.json == "$cur"* ]]; then
                        COMPREPLY+=("${prefix}plugin.json")
                    fi
                fi
                return 0
            fi
            while IFS= read -r -d '' path; do
                name="${path##*/}"
                name="${name%.json}"
                [[ -n "$name" ]] || continue
                if [[ "$name" != "$cur"* ]]; then
                    [[ "$cur" == *.j* && "$name.json" == "$cur"* ]] || continue
                    name="${name}.json"
                fi
                COMPREPLY+=("${prefix}${name}")
                if [[ "$name" == *[^a-zA-Z0-9_.-]* ]]; then
                    compopt -o filenames
                fi
            done < <(
                shopt -s nullglob dotglob
                shopt -u failglob
                for path in "$directory"/plugins/*.json; do
                    [[ -f "$path" ]] && printf '%s\0' "$path"
                done
            )
            ;;
    esac
    return 0
}

complete -F _autodownload_complete autodownload.py
