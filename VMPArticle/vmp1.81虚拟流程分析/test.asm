
    include \masm32\include\masm32rt.inc

    .data
      item dd 0deadbeefh

    .code

main proc
    mov eax, item
    add eax, 12345678h
    sub eax, 12345678h
    mov item, eax    
    ret

main endp



start:   

    call main
    exit



; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい?

end start
