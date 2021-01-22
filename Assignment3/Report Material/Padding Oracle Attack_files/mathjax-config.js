MathJax.Hub.Config({
    tex2jax: {
        inlineMath: [ ['$','$'], ['\\(', '\\)']  ]
    },
    TeX: {
        TagSide: "right",
        equationNumbers: {autoNumber: "AMS"},
        Macros: {
            // Add your macros here. Here are some examples.
            eps:        '\\varepsilon',
            cosec:      '\\operatorname{cosec}',
            abs:        [ '\\left\\lvert#1\\right\\rvert', 1 ],
            paren:      [ '#1(#2#1)', 2, '' ],
        }
    }
});
